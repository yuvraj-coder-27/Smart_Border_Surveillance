import cv2
import numpy as np
import time
import os
import folium
from folium.plugins import MarkerCluster, Fullscreen, MeasureControl, HeatMap
from datetime import datetime, timedelta
import webbrowser
import threading
import io
import logging
from PIL import Image, ImageDraw, ImageFont
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('MapVisualizer')

# Mock GPSD implementation for testing when no GPS device is available
class MockGPSD:
    def __init__(self, initial_lat=31.6042, initial_lon=74.5750):
        self.lat = initial_lat
        self.lon = initial_lon
        self.mode = 3
        self.movement_speed = 0.0001
        self.movement_direction = 0
        self.last_update = time.time()
    
    def get_current(self):
        current_time = time.time()
        time_diff = current_time - self.last_update
        if np.random.random() < 0.1:
            self.movement_direction = (self.movement_direction + np.random.uniform(-30, 30)) % 360
        self.lat += np.sin(np.radians(self.movement_direction)) * self.movement_speed * time_diff
        self.lon += np.cos(np.radians(self.movement_direction)) * self.movement_speed * time_diff
        self.last_update = current_time
        return self

try:
    import gpsd
    original_gpsd_connect = gpsd.connect
    def mock_gpsd_connect(host="localhost", port=2947):
        try:
            original_gpsd_connect(host, port)
            print("Connected to real GPSD service")
        except Exception as e:
            gpsd.get_current = lambda: MockGPSD(settings.DEFAULT_LAT, settings.DEFAULT_LON)
    gpsd.connect = mock_gpsd_connect
except ImportError:
    class DummyGPSDModule:
        @staticmethod
        def connect(host="localhost", port=2947):
            pass
        @staticmethod
        def get_current():
            return MockGPSD(settings.DEFAULT_LAT, settings.DEFAULT_LON)
    gpsd = DummyGPSDModule()

class Visualizer:
    """Handles visualization of detections and alerts on video frames"""
    
    def __init__(self):
        self.colors = {
            'person': (0, 255, 0),      # Green
            'car': (0, 165, 255),       # Orange
            'truck': (0, 0, 255),       # Red
            'motorcycle': (255, 0, 0),  # Blue
            'bicycle': (255, 0, 255),   # Purple
            'drone': (255, 255, 0),     # Cyan
            'backpack': (128, 0, 128),  # Purple
            'suitcase': (165, 42, 42),  # Brown
            'cell phone': (255, 191, 0), # Deep Sky Blue
            'handbag': (70, 130, 180),  # Steel Blue
            'fence_tampering': (0, 0, 255),  # Red
            'loitering': (0, 255, 255),      # Yellow
            'crawling': (255, 0, 255),       # Magenta
            'knife': (0, 0, 255),            # Red
            'border_crossing': (255, 0, 0),  # Red (bright)
            'default': (200, 200, 200)       # Gray
        }
        
        # Colors for display
        self.colors = {
            'person': (0, 255, 0),      # Green
            'car': (0, 165, 255),       # Orange
            'truck': (0, 0, 255),       # Red
            'motorcycle': (255, 0, 0),  # Blue
            'bicycle': (255, 0, 255),   # Purple
            'drone': (255, 255, 0),     # Cyan
            'backpack': (128, 0, 128),  # Purple
            'suitcase': (165, 42, 42),  # Brown
            'cell phone': (255, 191, 0), # Deep Sky Blue
            'handbag': (70, 130, 180),  # Steel Blue
            'fence_tampering': (0, 0, 255),  # Red
            'loitering': (0, 255, 255),      # Yellow
            'crawling': (255, 0, 255),       # Magenta
            'knife': (0, 0, 255),            # Red
            'border_crossing': (0, 0, 255),  # Red (bright)
            'intrusion': (0, 69, 255),       # Orange-Red
            'default': (200, 200, 200)       # Gray
        }
        
        # Font settings
        self.font = cv2.FONT_HERSHEY_SIMPLEX
        self.font_scale = 0.5
        self.font_thickness = 1
        
        # Track FPS
        self.prev_frame_time = 0
        self.fps = 0

    def draw_zones(self, frame, zones):
        """
        Draw restricted polygon zones on the frame with translucent fills and labels.
        """
        if not zones:
            return frame

        overlay = frame.copy()
        has_polys = False

        for zone in zones:
            points = zone.get("polygon_points", [])
            if len(points) >= 3:
                has_polys = True
                pts_arr = np.array(points, dtype=np.int32).reshape((-1, 1, 2))
                # Translucent fill in warning color
                cv2.fillPoly(overlay, [pts_arr], (0, 0, 180))
                # Distinct perimeter boundary line
                cv2.polylines(frame, [pts_arr], isClosed=True, color=(0, 60, 255), thickness=2)

                # Centroid for label
                cx = int(sum(float(p[0]) for p in points) / len(points))
                cy = int(sum(float(p[1]) for p in points) / len(points))
                label = f"RESTRICTED: {zone.get('name', 'ZONE')}"
                cv2.putText(frame, label, (int(max(10, cx - 60)), int(cy)), self.font, float(self.font_scale * 0.9), (0, 240, 255), 2)

        if has_polys:
            # 25% opacity overlay blend so camera video remains visible
            cv2.addWeighted(overlay, 0.25, frame, 0.75, 0, frame)

        return frame
    
    def draw_detections(self, frame, detections):
        """
        Draw bounding boxes and labels for detections with persistent track IDs.
        """
        for detection in detections:
            x1, y1, x2, y2, confidence, class_id, class_name = detection[:7]
            x1, y1, x2, y2 = int(x1), int(y1), int(x2), int(y2)
            track_id = detection[7] if len(detection) > 7 and detection[7] >= 0 else None
            
            # Get color for this class
            color = self.colors.get(class_name, self.colors['default'])
            
            # Draw bounding box
            cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
            
            # Create label with persistent track ID if available
            if track_id is not None:
                label = f"ID #{track_id} {class_name}: {confidence:.2f}"
            else:
                label = f"{class_name}: {confidence:.2f}"
            
            # Calculate label background size
            (label_width, label_height), _ = cv2.getTextSize(
                label, self.font, float(self.font_scale), int(self.font_thickness)
            )
            
            # Draw label background
            cv2.rectangle(
                frame, 
                (x1, max(0, y1 - label_height - 6)), 
                (x1 + label_width + 6, max(label_height + 6, y1)), 
                color, 
                -1
            )
            
            # Draw label text
            cv2.putText(
                frame, 
                label, 
                (x1 + 3, max(label_height, y1 - 4)), 
                self.font, 
                float(self.font_scale), 
                (255, 255, 255), 
                int(self.font_thickness)
            )
        
        return frame
    
    def draw_alerts(self, frame, alerts):
        """
        Draw visual indicators for alerts
        """
        if not alerts:
            return frame

        for alert in alerts:
            alert_type = alert.get('type', 'perimeter_anomaly')
            color = self.colors.get(alert_type, self.colors['default'])
            msg = alert.get('message', str(alert_type))
            
            if 'bbox' in alert and alert['bbox']:
                x1, y1, x2, y2 = [int(v) for v in alert['bbox']]
                cv2.rectangle(frame, (x1, y1), (x2, y2), color, 3)
                
                # Corner reticles for high-impact tactical look
                c_len = min(15, max(4, (x2 - x1) // 4))
                cv2.line(frame, (x1, y1), (x1 + c_len, y1), (0, 255, 255), 3)
                cv2.line(frame, (x1, y1), (x1, y1 + c_len), (0, 255, 255), 3)
                cv2.line(frame, (x2, y2), (x2 - c_len, y2), (0, 255, 255), 3)
                cv2.line(frame, (x2, y2), (x2, y2 - c_len), (0, 255, 255), 3)

                cv2.putText(
                    frame,
                    f"THREAT: {msg}",
                    (x1, max(20, y1 - 10)),
                    self.font,
                    float(self.font_scale * 0.9),
                    (0, 255, 255),
                    2
                )
            
            elif alert_type == 'fence_tampering':
                region_id = alert.get('region_id', 0)
                cv2.putText(
                    frame,
                    f"PERIMETER TAMPER: {msg}",
                    (10, 40 + region_id * 30),
                    self.font,
                    self.font_scale * 1.1,
                    (0, 0, 255),
                    2
                )
        
        return frame
    
    def add_info_overlay(self, frame, num_detections=0):
        """
        Add information overlay with timestamp, FPS, etc.
        
        Args:
            frame: OpenCV image to draw on
            num_detections: Number of detections in the frame
            
        Returns:
            frame: The image with info overlay
        """
        # Calculate FPS
        current_time = time.time()
        self.fps = 1 / (current_time - self.prev_frame_time) if self.prev_frame_time > 0 else 0
        self.prev_frame_time = current_time
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Draw black background for overlay
        height, width = frame.shape[:2]
        cv2.rectangle(frame, (0, height - 40), (width, height), (0, 0, 0), -1)
        
        # Draw timestamp
        cv2.putText(
            frame,
            timestamp,
            (10, height - 15),
            self.font,
            self.font_scale * 1.2,
            (255, 255, 255),
            self.font_thickness
        )
        
        # Draw FPS
        fps_text = f"FPS: {self.fps:.1f}"
        cv2.putText(
            frame,
            fps_text,
            (width - 120, height - 15),
            self.font,
            self.font_scale * 1.2,
            (255, 255, 255),
            self.font_thickness
        )
        
        # Draw detection count
        count_text = f"Detections: {num_detections}"
        cv2.putText(
            frame,
            count_text,
            (width - 250, height - 15),
            self.font,
            self.font_scale * 1.2,
            (255, 255, 255),
            self.font_thickness
        )
        
        return frame
    
    def draw_fence_regions(self, frame, fence_regions):
        """
        Draw fence region outlines
        
        Args:
            frame: OpenCV image to draw on
            fence_regions: List of polygon coordinates
            
        Returns:
            frame: The image with fence regions drawn
        """
        for i, region in enumerate(fence_regions):
            if region:
                points = np.array(region, np.int32).reshape((-1, 1, 2))
                cv2.polylines(frame, [points], True, (0, 255, 255), 2)
                
                # Add region label
                centroid_x = sum(p[0] for p in region) // len(region)
                centroid_y = sum(p[1] for p in region) // len(region)
                
                cv2.putText(
                    frame,
                    f"Fence {i+1}",
                    (centroid_x, centroid_y),
                    self.font,
                    self.font_scale,
                    (0, 255, 255),
                    self.font_thickness
                )
        
        return frame
    
    def create_snapshot(self, frame, alert=None):
        """
        Create a snapshot image with alert details for saving
        
        Args:
            frame: OpenCV image to create snapshot from
            alert: Alert information to include
            
        Returns:
            snapshot: Annotated snapshot image
        """
        snapshot = frame.copy()
        
        # Add timestamp and large alert banner
        if alert:
            # Add red banner at the top
            height, width = snapshot.shape[:2]
            cv2.rectangle(snapshot, (0, 0), (width, 60), (0, 0, 255), -1)
            
            # Add alert text
            cv2.putText(
                snapshot,
                f"ALERT: {alert['type'].upper()} - {alert['message']}",
                (10, 40),
                self.font,
                1.2,
                (255, 255, 255),
                2
            )
            
            # Add timestamp at the bottom
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cv2.putText(
                snapshot,
                timestamp,
                (10, height - 10),
                self.font,
                0.8,
                (255, 255, 255),
                1
            )
        
        return snapshot
    
    def draw_border_lines(self, frame, border_lines):
        """
        Draw border lines on the frame
        
        Args:
            frame: OpenCV image to draw on
            border_lines: List of border line definitions
            
        Returns:
            frame: The image with border lines drawn
        """
        for border in border_lines:
            points = border['points']
            border_id = border.get('id', 'default')
            direction = border.get('direction', 'both')
            
            # Draw the border line
            cv2.line(
                frame,
                (points[0][0], points[0][1]),
                (points[1][0], points[1][1]),
                (0, 0, 255),  # Red color for borders
                2,
                cv2.LINE_AA
            )
            
            # Add border label
            mid_x = (points[0][0] + points[1][0]) // 2
            mid_y = (points[0][1] + points[1][1]) // 2
            
            # Add a small offset to the label position
            label_offset_x = 5
            label_offset_y = -10
            
            # Create label text
            label = f"Border: {border_id}"
            
            # Draw label background
            (label_width, label_height), _ = cv2.getTextSize(
                label, self.font, self.font_scale, self.font_thickness
            )
            
            cv2.rectangle(
                frame,
                (mid_x + label_offset_x, mid_y + label_offset_y - label_height - 5),
                (mid_x + label_offset_x + label_width + 5, mid_y + label_offset_y),
                (0, 0, 255),
                -1
            )
            
            # Draw label text
            cv2.putText(
                frame,
                label,
                (mid_x + label_offset_x + 3, mid_y + label_offset_y - 4),
                self.font,
                self.font_scale,
                (255, 255, 255),
                self.font_thickness
            )
            
            # Draw direction indicators
            if direction == 'north_to_south' or direction == 'both':
                # Draw arrow pointing south
                cv2.arrowedLine(
                    frame,
                    (mid_x + 20, mid_y - 10),
                    (mid_x + 20, mid_y + 10),
                    (0, 0, 255),
                    1,
                    cv2.LINE_AA,
                    tipLength=0.3
                )
            
            if direction == 'south_to_north' or direction == 'both':
                # Draw arrow pointing north
                cv2.arrowedLine(
                    frame,
                    (mid_x - 20, mid_y + 10),
                    (mid_x - 20, mid_y - 10),
                    (0, 0, 255),
                    1,
                    cv2.LINE_AA,
                    tipLength=0.3
                )
        
        return frame

class GeoMapVisualizer:
    """Handles visualization of detections on geographical maps"""
    
    def __init__(self):
        """Initialize the geographical map visualizer"""
        self.location = [settings.DEFAULT_LAT, settings.DEFAULT_LON]
        self.detection_points = []
        self.detection_history = []
        self.last_update_time = 0
        self.map = None
        self.connected_to_gps = False
        self.time_filters = {
            'last_hour': datetime.now() - timedelta(hours=1),
            'last_day': datetime.now() - timedelta(days=1),
            'last_week': datetime.now() - timedelta(weeks=1),
            'all': None
        }
        self.active_time_filter = 'all'
        self.detection_types = set()
        self.detection_type_filters = set()
        self.init_map()
        
    def init_map(self):
        """Initialize the map with default settings"""
        try:
            # Ensure output directory exists
            output_dir = os.path.dirname(os.path.abspath(settings.MAP_OUTPUT_FILE))
            os.makedirs(output_dir, exist_ok=True)
            
            # Create initial map
            self.map = folium.Map(
                location=self.location,
                zoom_start=settings.MAP_ZOOM_LEVEL,
                tiles=settings.MAP_TILE_PROVIDER
            )
            
            # Add fullscreen and measurement controls
            Fullscreen().add_to(self.map)
            MeasureControl().add_to(self.map)
            
            # Add marker cluster for detections
            self.marker_cluster = MarkerCluster().add_to(self.map)
            
            # Create feature groups for different detection types
            self.people_layer = folium.FeatureGroup(name="People").add_to(self.map)
            self.vehicles_layer = folium.FeatureGroup(name="Vehicles").add_to(self.map)
            self.items_layer = folium.FeatureGroup(name="Items").add_to(self.map)
            self.alerts_layer = folium.FeatureGroup(name="Alerts", show=True).add_to(self.map)
            
            # Create a layer for current location
            self.location_layer = folium.FeatureGroup(name="Current Location").add_to(self.map)
            
            # Add heatmap layer
            self.heatmap_layer = folium.FeatureGroup(name="Detection Heatmap").add_to(self.map)
            
            # Add layer control
            folium.LayerControl().add_to(self.map)
            
            # Add searchable legend
            self._add_legend_control()
            
            # Save initial map
            map_file_path = os.path.abspath(str(settings.MAP_OUTPUT_FILE))
            self.map.save(map_file_path)
            
            # Try to connect to GPS
            self.connect_to_gps()
            
        except Exception as e:
            logging.error(f"Error initializing map: {str(e)}")
    
    def _add_legend_control(self):
        """Add a custom legend control to the map"""
        legend_html = """
        <div id="mapLegend" style="position: absolute; z-index:9999; background-color:rgba(255,255,255,0.9); 
                padding: 10px; border-radius: 5px; bottom: 30px; right: 10px; max-width: 250px;">
            <h4 style="margin-top: 0;">Map Legend</h4>
            <div><i style="background: #00FF00; width: 15px; height: 15px; display: inline-block; border-radius: 50%;"></i> Person</div>
            <div><i style="background: #FF6600; width: 15px; height: 15px; display: inline-block; border-radius: 50%;"></i> Vehicle</div>
            <div><i style="background: #0066FF; width: 15px; height: 15px; display: inline-block; border-radius: 50%;"></i> Item</div>
            <div><i style="background: #FF0000; width: 15px; height: 15px; display: inline-block; border-radius: 50%;"></i> Alert</div>
            <div><i style="background: blue; width: 15px; height: 15px; display: inline-block; border-radius: 50%;"></i> Current Location</div>
            <div><i style="background: red; width: 20px; height: 3px; display: inline-block;"></i> Border</div>
        </div>
        """
        self.map.get_root().html.add_child(folium.Element(legend_html))
    
    def connect_to_gps(self):
        """Connect to GPSD service"""
        try:
            gpsd.connect(settings.GPSD_HOST, settings.GPSD_PORT)
            self.connected_to_gps = True
            
            # Start updating location in a background thread
            threading.Thread(target=self.update_location_thread, daemon=True).start()
            logger.info("Connected to GPS service")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to GPS: {str(e)}")
            self.connected_to_gps = False
            return False
    
    def update_location_thread(self):
        """Background thread to update location from GPS"""
        while self.connected_to_gps:
            try:
                current = gpsd.get_current()
                self.location = [current.lat, current.lon]
                if time.time() - self.last_update_time > settings.MAP_UPDATE_INTERVAL:
                    self.update_map()
            except Exception as e:
                logger.error(f"Error updating location: {str(e)}")
            
            time.sleep(1)  # Update every second
    
    def add_detection(self, detection_type, lat=None, lon=None, confidence=0.0, timestamp=None, additional_data=None):
        """
        Add a detection point to the map
        
        Args:
            detection_type: Type of detection (person, vehicle, item, etc.)
            lat: Latitude (optional, uses current location if None)
            lon: Longitude (optional, uses current location if None)
            confidence: Detection confidence score
            timestamp: Detection time (defaults to now)
            additional_data: Dictionary with any additional data to store
        """
        # Use current location if lat/lon not provided
        if lat is None or lon is None:
            lat, lon = self.location
        
        # Use current time if timestamp not provided
        if timestamp is None:
            timestamp = datetime.now()
        elif isinstance(timestamp, str):
            # Convert string timestamp to datetime
            timestamp = datetime.fromisoformat(timestamp)
            
        # Store the detection type for filtering
        self.detection_types.add(detection_type)
        
        # Prepare detection data
        detection = {
            'type': detection_type,
            'lat': lat,
            'lon': lon,
            'confidence': confidence,
            'timestamp': timestamp.isoformat(),
            'data': additional_data or {}
        }
        
        # Add to detection points list
        self.detection_points.append(detection)
        
        # Also add to historical data
        self.detection_history.append(detection)
        
        # Keep detection history to a reasonable size (last 1000 detections)
        if len(self.detection_history) > 1000:
            self.detection_history = self.detection_history[-1000:]
            
        # Update the map if enough time has passed
        if time.time() - self.last_update_time > settings.MAP_UPDATE_INTERVAL:
            self.update_map()
            
        return True
    
    def update_map(self):
        """Update the map with current location and all detection points"""
        try:
            # Clear previous markers
            self.map = folium.Map(
                location=self.location,
                zoom_start=settings.MAP_ZOOM_LEVEL,
                tiles=settings.MAP_TILE_PROVIDER
            )
            
            # Add controls
            Fullscreen().add_to(self.map)
            MeasureControl().add_to(self.map)
            
            # Add current location marker
            self.location_layer = folium.FeatureGroup(name="Current Location").add_to(self.map)
            folium.Marker(
                location=self.location,
                popup="Current Location",
                icon=folium.Icon(color="blue", icon="info-sign")
            ).add_to(self.location_layer)
            
            # Create feature groups for different detection types
            self.people_layer = folium.FeatureGroup(name="People").add_to(self.map)
            self.vehicles_layer = folium.FeatureGroup(name="Vehicles").add_to(self.map)
            self.items_layer = folium.FeatureGroup(name="Items").add_to(self.map)
            self.alerts_layer = folium.FeatureGroup(name="Alerts", show=True).add_to(self.map)
            
            # Create a new marker cluster
            self.marker_cluster = MarkerCluster(name="All Detections").add_to(self.map)
            
            # Create heatmap layer
            self.heatmap_layer = folium.FeatureGroup(name="Detection Heatmap").add_to(self.map)
            
            # Create border layer
            self.border_layer = folium.FeatureGroup(name="Border Lines").add_to(self.map)
            
            # Add borders if enabled
            if hasattr(settings, 'MAP_BORDERS_ENABLED') and settings.MAP_BORDERS_ENABLED:
                for border in settings.MAP_BORDERS:
                    # Create a polyline for each border
                    folium.PolyLine(
                        locations=border['coordinates'],
                        popup=border['name'],
                        color=border['color'],
                        weight=border['weight'],
                        opacity=0.8,
                        tooltip=f"Border: {border['name']}"
                    ).add_to(self.border_layer)
            
            # Filter detection points based on active time filter
            filtered_points = self.get_filtered_detections()
            
            # Prepare heatmap data
            heatmap_data = []
            
            # Add markers for each detection point
            for point in filtered_points:
                # Get details
                point_type = point['type']
                lat = point['lat']
                lon = point['lon']
                confidence = point.get('confidence', 0.0)
                timestamp = point.get('timestamp', datetime.now().isoformat())
                
                # Format datetime for display
                try:
                    dt = datetime.fromisoformat(timestamp)
                    formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    formatted_time = timestamp
                
                # Choose icon color based on detection type
                if point_type in ['person']:
                    icon_color = 'green'
                    target_layer = self.people_layer
                elif point_type in ['car', 'truck', 'motorcycle', 'bicycle']:
                    icon_color = 'orange'
                    target_layer = self.vehicles_layer
                elif point_type in ['backpack', 'suitcase', 'handbag', 'cell phone', 'knife', 'gun']:
                    icon_color = 'blue'
                    target_layer = self.items_layer
                else:
                    icon_color = 'gray'
                    target_layer = self.marker_cluster
                
                # Choose icon based on detection type
                if point_type == 'person':
                    icon_type = 'user'
                elif point_type in ['car', 'truck', 'motorcycle']:
                    icon_type = 'car'
                elif point_type == 'bicycle':
                    icon_type = 'bicycle'
                elif point_type in ['knife', 'gun']:
                    icon_type = 'warning-sign'
                    icon_color = 'red'
                    target_layer = self.alerts_layer
                else:
                    icon_type = 'map-marker'
                
                # Create detailed popup content
                popup_content = f"""
                <div style="font-family: Arial; min-width: 180px;">
                    <h4 style="margin-bottom: 5px;">{point_type.title()}</h4>
                    <p><strong>Time:</strong> {formatted_time}</p>
                    <p><strong>Confidence:</strong> {confidence:.2f}</p>
                    <p><strong>Location:</strong> {lat:.6f}, {lon:.6f}</p>
                """
                
                # Add any additional data to popup
                if 'data' in point and point['data']:
                    popup_content += "<p><strong>Additional Data:</strong></p><ul>"
                    for k, v in point['data'].items():
                        popup_content += f"<li>{k}: {v}</li>"
                    popup_content += "</ul>"
                
                popup_content += "</div>"
                
                # Create marker with popup
                folium.Marker(
                    location=[lat, lon],
                    popup=folium.Popup(popup_content, max_width=300),
                    tooltip=f"{point_type.title()} ({formatted_time})",
                    icon=folium.Icon(color=icon_color, icon=icon_type, prefix='fa')
                ).add_to(target_layer)
                
                # Add point to heatmap data
                heatmap_data.append([lat, lon, min(confidence * 2, 1.0)])  # Weight by confidence
            
            # Add time-filtered control
            self._add_time_filter_control()
            
            # Add detection type filter control
            self._add_type_filter_control()
            
            # Add heatmap to the map if we have data and it's enabled
            if heatmap_data and self.heatmap_enabled:
                HeatMap(
                    heatmap_data,
                    radius=15,
                    blur=10,
                    gradient={0.2: 'blue', 0.4: 'lime', 0.6: 'yellow', 0.8: 'orange', 1: 'red'}
                ).add_to(self.heatmap_layer)
            
            # Add layer control with expanded view
            folium.LayerControl(collapsed=False).add_to(self.map)
            
            # Add legend
            self._add_legend_control()
            
            # Save updated map
            self.save_map()
            
            # Update last update time
            self.last_update_time = time.time()
            
        except Exception as e:
            print(f"Error updating map: {str(e)}")
    
    def _add_time_filter_control(self):
        """Add time filter control to the map"""
        # Create HTML for time filter control
        time_filter_html = """
        <div id="timeFilter" style="position: absolute; z-index:9999; background-color:rgba(255,255,255,0.9); 
                padding: 10px; border-radius: 5px; top: 10px; right: 10px; max-width: 200px;">
            <h4 style="margin-top: 0;">Time Filter</h4>
            <form id="timeFilterForm">
                <div><input type="radio" name="timeFilter" value="last_hour" id="last_hour"> <label for="last_hour">Last Hour</label></div>
                <div><input type="radio" name="timeFilter" value="last_day" id="last_day"> <label for="last_day">Last 24 Hours</label></div>
                <div><input type="radio" name="timeFilter" value="last_week" id="last_week"> <label for="last_week">Last Week</label></div>
                <div><input type="radio" name="timeFilter" value="all" id="all" checked> <label for="all">All Time</label></div>
            </form>
        </div>
        """
        
        # Create JavaScript separately to avoid comment syntax issues
        time_js_script = """
        <script>
            document.getElementById('timeFilterForm').addEventListener('change', function(e) {
                // In a real app, this would update via AJAX
                console.log('Time filter changed to:', e.target.value);
                // For demo, just reload the page with the filter
                //window.location.href = window.location.pathname + '?timeFilter=' + e.target.value;
            });
        </script>
        """
        
        # Combine HTML and JavaScript
        full_time_html = time_filter_html + time_js_script
        self.map.get_root().html.add_child(folium.Element(full_time_html))
    
    def _add_type_filter_control(self):
        """Add detection type filter control to the map"""
        # Generate checkboxes for each detection type
        checkboxes_html = ""
        for detection_type in sorted(self.detection_types):
            checkboxes_html += f"""
            <div><input type="checkbox" name="typeFilter" value="{detection_type}" id="{detection_type}" checked> 
            <label for="{detection_type}">{detection_type.title()}</label></div>
            """
        
        # Create HTML for type filter control
        type_filter_html = f"""
        <div id="typeFilter" style="position: absolute; z-index:9999; background-color:rgba(255,255,255,0.9); 
                padding: 10px; border-radius: 5px; top: 180px; right: 10px; max-width: 200px;">
            <h4 style="margin-top: 0;">Detection Types</h4>
            <form id="typeFilterForm">
                {checkboxes_html}
            </form>
        </div>
        """
        
        # Create JavaScript separately to avoid comment syntax issues
        js_script = """
        <script>
            document.getElementById('typeFilterForm').addEventListener('change', function(e) {
                // In a real app, this would update via AJAX
                console.log('Type filter changed:', e.target.value, e.target.checked);
            });
        </script>
        """
        
        # Combine HTML and JavaScript
        full_html = type_filter_html + js_script
        self.map.get_root().html.add_child(folium.Element(full_html))
    
    def get_filtered_detections(self):
        """Get detection points filtered by the active time filter and type filters"""
        # Start with all points
        filtered_points = self.detection_points.copy()
        
        # Apply time filter if active
        if self.active_time_filter != 'all' and self.active_time_filter in self.time_filters:
            cutoff_time = self.time_filters[self.active_time_filter]
            if cutoff_time:
                filtered_points = [
                    p for p in filtered_points 
                    if datetime.fromisoformat(p['timestamp']) >= cutoff_time
                ]
        
        # Apply type filters if any are active
        if self.detection_type_filters:
            filtered_points = [
                p for p in filtered_points
                if p['type'] in self.detection_type_filters
            ]
            
        return filtered_points
    
    def set_time_filter(self, filter_name):
        """Set the active time filter"""
        if filter_name in self.time_filters:
            self.active_time_filter = filter_name
            # Update the time filters with current timestamps
            self.time_filters = {
                'last_hour': datetime.now() - timedelta(hours=1),
                'last_day': datetime.now() - timedelta(days=1),
                'last_week': datetime.now() - timedelta(weeks=1),
                'all': None
            }
            self.update_map()
            return True
        return False
    
    def toggle_detection_type_filter(self, detection_type, active=True):
        """Toggle a detection type filter on or off"""
        if active:
            self.detection_type_filters.add(detection_type)
        else:
            self.detection_type_filters.discard(detection_type)
        self.update_map()
        return True
    
    def clear_all_filters(self):
        """Clear all filters"""
        self.active_time_filter = 'all'
        self.detection_type_filters.clear()
        self.update_map()
        return True
    
    def save_map(self):
        """Save the map to an HTML file"""
        try:
            # Ensure the output directory exists
            output_dir = os.path.dirname(settings.MAP_OUTPUT_FILE)
            os.makedirs(output_dir, exist_ok=True)
            
            # Make sure the MAP_OUTPUT_FILE is a string, not a float or other type
            map_file = str(settings.MAP_OUTPUT_FILE)
            
            # Save the map
            self.map.save(map_file)
            return True
        except Exception as e:
            logging.error(f"Error saving map: {str(e)}")
            return False

    # Add property for heatmap
    @property
    def heatmap_enabled(self):
        """Get heatmap enabled state from settings if available"""
        # Default to True if not set
        return getattr(settings, 'HEATMAP_ENABLED', True)
        
    def get_map_image(self, width, height):
        """
        Generate an image of the current map for display or inspection
        
        Args:
            width: Desired image width
            height: Desired image height
            
        Returns:
            PIL.Image.Image: Rendered map summary image
        """
        try:
            # Make sure the map is saved
            self.save_map()
            
            # Use a browser automation approach to render the HTML map to image
            # Since we can't directly render HTML in Python, we'll create a static image
            # from the saved HTML file
            
            # Create a simple image with map information
            img = Image.new('RGB', (width, height), color=(245, 245, 245))
            draw = ImageDraw.Draw(img)
            
            # Try to use a nice font
            try:
                font = ImageFont.truetype("Arial", 16)
                small_font = ImageFont.truetype("Arial", 12)
            except:
                font = ImageFont.load_default()
                small_font = ImageFont.load_default()
            
            # Add title and instructions
            draw.text((20, 20), "Interactive Geo Map", fill=(0, 0, 0), font=font)
            draw.text((20, 60), f"Current Location: {self.location[0]:.6f}, {self.location[1]:.6f}", 
                     fill=(0, 0, 0), font=small_font)
            draw.text((20, 90), f"Total Detection Points: {len(self.detection_points)}", 
                     fill=(0, 0, 0), font=small_font)
            
            # Add information about the map file
            draw.text((20, 130), "The interactive map is available at:", fill=(0, 0, 0), font=small_font)
            draw.text((20, 150), settings.MAP_OUTPUT_FILE, fill=(0, 0, 255), font=small_font)
            
            # Add instructions to view the map
            y_pos = 200
            instructions = [
                "To view the interactive map with all detection points:",
                "1. Click 'Open in Browser' to see the full interactive map",
                "2. Use the layer controls to toggle different detection types",
                "3. Click on detection points to see details",
                "4. Use the time filter to show detections from different periods"
            ]
            
            for line in instructions:
                draw.text((20, y_pos), line, fill=(0, 0, 0), font=small_font)
                y_pos += 25
            
            # Create a button-like area
            button_x, button_y = width // 2 - 100, height - 100
            draw.rectangle([(button_x, button_y), (button_x + 200, button_y + 40)], 
                          fill=(70, 130, 180), outline=(0, 0, 0))
            draw.text((button_x + 30, button_y + 12), "Open Interactive Map", fill=(255, 255, 255), font=font)
            
            # Return PIL image directly
            return img
            
        except Exception as e:
            logging.error(f"Error generating map image: {str(e)}")
            
            # Return a basic error image
            img = Image.new('RGB', (width, height), color=(240, 240, 240))
            draw = ImageDraw.Draw(img)
            try:
                font = ImageFont.truetype("Arial", 16)
            except:
                font = ImageFont.load_default()
                
            draw.text((20, 20), "Map Visualization Error", fill=(255, 0, 0), font=font)
            draw.text((20, 60), str(e), fill=(0, 0, 0), font=font)
            draw.text((20, 100), "Please check console for details.", fill=(0, 0, 0), font=font)
            
            return img
            
    def open_map_in_browser(self):
        """
        Open the generated map in the default web browser
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Make sure map is saved
            self.save_map()
            
            # Open the map file in the browser
            map_path = os.path.abspath(settings.MAP_OUTPUT_FILE)
            webbrowser.open(f"file://{map_path}")
            return True
        except Exception as e:
            logging.error(f"Error opening map in browser: {str(e)}")
            return False
            
    def generate_mock_data(self, num_points=20, spread_km=5):
        """
        Generate mock detection data around the current location
        
        Args:
            num_points: Number of mock detection points to generate
            spread_km: Approximate spread in kilometers around current location
            
        Returns:
            bool: True if successful
        """
        try:
            # Detection types to randomly choose from
            detection_types = [
                'person', 'car', 'truck', 'motorcycle', 'bicycle', 
                'backpack', 'suitcase', 'cell phone', 'knife'
            ]
            
            # Create timestamps spanning the last 24 hours
            now = datetime.now()
            
            # Get the base location from current location
            base_lat, base_lon = self.location
            
            # Approximate conversion from kilometers to degrees (varies by latitude)
            # At the equator, 1 degree is about 111 km
            lat_offset_per_km = 1 / 111.0  # degrees per km
            lon_offset_per_km = 1 / (111.0 * np.cos(np.radians(base_lat)))  # degrees per km
            
            # Generate random points
            for i in range(num_points):
                # Random type
                detection_type = np.random.choice(detection_types)
                
                # Random position around base location
                # Using normal distribution for more realistic clustering
                lat_offset = np.random.normal(0, spread_km * lat_offset_per_km / 2)
                lon_offset = np.random.normal(0, spread_km * lon_offset_per_km / 2)
                
                lat = base_lat + lat_offset
                lon = base_lon + lon_offset
                
                # Random timestamp within the last 24 hours
                hours_ago = np.random.uniform(0, 24)
                timestamp = now - timedelta(hours=hours_ago)
                
                # Random confidence
                confidence = np.random.uniform(0.6, 0.98)
                
                # Add additional data based on type
                additional_data = {}
                
                if detection_type in ['person']:
                    additional_data['movement'] = np.random.choice(['walking', 'running', 'stationary'])
                    additional_data['estimated_height'] = f"{np.random.uniform(1.5, 2.0):.2f}m"
                    
                elif detection_type in ['car', 'truck', 'motorcycle']:
                    additional_data['speed'] = f"{np.random.uniform(0, 80):.1f} km/h"
                    additional_data['direction'] = np.random.choice(['north', 'south', 'east', 'west'])
                    
                elif detection_type in ['backpack', 'suitcase', 'cell phone']:
                    additional_data['size'] = np.random.choice(['small', 'medium', 'large'])
                    
                # Add a special alert for knives
                if detection_type == 'knife':
                    additional_data['alert_level'] = 'high'
                    additional_data['action_required'] = 'immediate inspection'
                
                # Add detection to the map
                self.add_detection(
                    detection_type=detection_type,
                    lat=lat,
                    lon=lon,
                    confidence=confidence,
                    timestamp=timestamp,
                    additional_data=additional_data
                )
            
            # Add a special border crossing alert
            border_lat = base_lat + np.random.normal(0, spread_km * lat_offset_per_km / 3)
            border_lon = base_lon + np.random.normal(0, spread_km * lon_offset_per_km / 3)
            border_timestamp = now - timedelta(minutes=np.random.uniform(5, 60))
            
            self.add_detection(
                detection_type='border_crossing',
                lat=border_lat,
                lon=border_lon,
                confidence=0.92,
                timestamp=border_timestamp,
                additional_data={
                    'direction': 'south_to_north',
                    'group_size': np.random.randint(1, 4),
                    'alert_level': 'critical',
                    'response_status': 'pending'
                }
            )
            
            # Update the map
            self.update_map()
            return True
            
        except Exception as e:
            logging.error(f"Error generating mock data: {str(e)}")
            return False