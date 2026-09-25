import os
import cv2
import numpy as np
import time
from ultralytics import YOLO
import torch

from config import settings
from utils.logger import logger

# ---------------------------------------------------------------------------
# Optional AI sub-module imports (graceful fallback if not available)
# ---------------------------------------------------------------------------
try:
    from ai.condition_classifier.classifier import FrameConditionClassifier
    _CONDITION_CLASSIFIER_AVAILABLE = True
except ImportError as _e:
    logger.warning(f"FrameConditionClassifier not available: {_e}")
    _CONDITION_CLASSIFIER_AVAILABLE = False
    FrameConditionClassifier = None  # type: ignore[assignment,misc]

try:
    from ai.tracking.bytetrack import BYTETracker
    _BYTETRACKER_AVAILABLE = True
except ImportError as _e:
    logger.warning(f"BYTETracker not available: {_e}")
    _BYTETRACKER_AVAILABLE = False
    BYTETracker = None  # type: ignore[assignment,misc]

class ObjectDetector:
    """YOLOv8-based object detection for border surveillance"""
    
    def __init__(self):
        # Load YOLO model
        model_path = os.path.join(settings.MODELS_DIR, "yolov8n.pt")
        if not os.path.exists(model_path):
            logger.info(f"Model not found at {model_path}, downloading YOLOv8n...")
            self.model = YOLO("yolov8n.pt")
            # Save the model for future use
            if not os.path.exists(settings.MODELS_DIR):
                os.makedirs(settings.MODELS_DIR)
            self.model.save(model_path)
        else:
            logger.info(f"Loading model from {model_path}")
            self.model = YOLO(model_path)
        
        # Set device and optimize model with CUDA Tensor Cores
        self.device = "cuda" if settings.USE_GPU and torch.cuda.is_available() else "cpu"
        logger.info(f"Using device: {self.device}")
        self.model.to(self.device)
        if self.device == "cuda":
            try:
                self.model.model.half()
                logger.info("YOLOv8 accelerated with native CUDA FP16 Tensor Cores.")
            except Exception as e:
                logger.warning(f"Could not enable FP16 model: {e}")
        
        # Set detection threshold
        self.threshold = settings.DETECTION_THRESHOLD
        
        # Initialize trackers for behavior analysis
        self.tracked_objects = {}  # Format: {id: {first_seen: timestamp, positions: [positions], etc}}
        self._frame_count = 0
        self._cached_condition = "daylight"

        # ---------------------------------------------------------------------------
        # Condition classifier – enhances frames before inference
        # ---------------------------------------------------------------------------
        if _CONDITION_CLASSIFIER_AVAILABLE:
            self.condition_classifier = FrameConditionClassifier()
            logger.info("FrameConditionClassifier initialised.")
        else:
            self.condition_classifier = None
            logger.warning("FrameConditionClassifier unavailable – running without it.")

        # ---------------------------------------------------------------------------
        # ByteTracker – persistent track IDs across frames
        # ---------------------------------------------------------------------------
        if _BYTETRACKER_AVAILABLE:
            self.byte_tracker = BYTETracker(
                track_thresh=0.5,
                track_buffer=30,
                match_thresh=0.8,
                frame_rate=getattr(settings, "FPS", 20),
            )
            logger.info("BYTETracker initialised.")
        else:
            self.byte_tracker = None
            logger.warning("BYTETracker unavailable – running without tracking.")
    
    def detect(self, frame):
        """
        Detect objects in a frame with high-throughput GPU acceleration.
        """
        self._frame_count += 1

        # ------------------------------------------------------------------
        # Step 1: Classify & enhance frame visibility (periodically cached)
        # ------------------------------------------------------------------
        if self.condition_classifier is not None:
            if self._frame_count % 15 == 1 or self._cached_condition is None:
                self._cached_condition = self.condition_classifier.classify(frame)
            condition = self._cached_condition
            if condition != "daylight":
                frame = self.condition_classifier.enhance(frame, condition)
        else:
            condition = "daylight"

        # ------------------------------------------------------------------
        # Step 2: Run YOLO inference with full FP16 Tensor Core acceleration
        # ------------------------------------------------------------------
        with torch.inference_mode():
            results = self.model(
                frame,
                conf=self.threshold,
                device=self.device,
                verbose=False,
                imgsz=settings.FRAME_HEIGHT
            )
        
        # ------------------------------------------------------------------
        # Step 3: Fast bulk extraction and filter predictions
        # ------------------------------------------------------------------
        detections = []
        for result in results:
            boxes = result.boxes
            if len(boxes) == 0:
                continue
            xyxy_all = boxes.xyxy.cpu().numpy()
            conf_all = boxes.conf.cpu().numpy()
            cls_all = boxes.cls.cpu().numpy()
            for i in range(len(boxes)):
                class_id = int(cls_all[i])
                class_name = self.model.names[class_id]
                if class_name in settings.CLASSES_OF_INTEREST:
                    x1, y1, x2, y2 = xyxy_all[i]
                    detections.append([
                        int(x1), int(y1), int(x2), int(y2),
                        float(conf_all[i]), class_id, class_name,
                        condition,
                    ])
        
        return detections

    def detect_and_track(self, frame, camera_id: str = "cam0") -> list:
        """
        Detect objects and return results enriched with persistent track IDs.

        Calls :meth:`detect` internally, then passes the detections through
        the BYTETracker to assign globally-unique, frame-persistent track IDs.

        Args:
            frame:     OpenCV image (numpy array, BGR)
            camera_id: Identifier of the camera producing this frame.

        Returns:
            list of detection lists:
                [x1, y1, x2, y2, confidence, class_id, class_name, track_id, visibility_condition]
        """
        raw_detections = self.detect(frame)
        frame_size = (frame.shape[1], frame.shape[0])  # (width, height)

        if self.byte_tracker is None:
            # Fallback – return detections with track_id = -1
            return [
                [
                    d[0], d[1], d[2], d[3],
                    d[4], d[5], d[6],
                    -1,
                    d[7] if len(d) > 7 else "daylight",
                ]
                for d in raw_detections
            ]

        # Build input for BYTETracker
        tracker_input = [
            {
                "bbox": [float(d[0]), float(d[1]), float(d[2]), float(d[3])],
                "score": float(d[4]),
                "class_name": d[6],
                "class_id": d[5],
                "condition": d[7] if len(d) > 7 else "daylight",
            }
            for d in raw_detections
        ]

        tracked = self.byte_tracker.update(tracker_input, frame_size)

        results_out = []
        used_raw_indices = set()

        for t in tracked:
            t_bbox = t["bbox"]
            bx1, by1 = int(round(t_bbox[0])), int(round(t_bbox[1]))
            bx2, by2 = int(round(t_bbox[2])), int(round(t_bbox[3]))

            # Find matching raw detection to preserve exact class_id and visibility condition
            best_idx = None
            best_dist = float("inf")
            for idx, d in enumerate(raw_detections):
                if d[6] == t.get("class_name", d[6]):
                    dist = abs(d[0] - bx1) + abs(d[1] - by1) + abs(d[2] - bx2) + abs(d[3] - by2)
                    if dist < best_dist:
                        best_dist = dist
                        best_idx = idx

            if best_idx is not None and best_idx not in used_raw_indices:
                used_raw_indices.add(best_idx)
                d = raw_detections[best_idx]
                class_id = d[5]
                condition = d[7] if len(d) > 7 else "daylight"
            else:
                class_id = 0
                condition = "daylight"

            results_out.append([
                bx1, by1, bx2, by2,
                float(t["score"]),
                class_id,
                t["class_name"],
                int(t["track_id"]),
                condition,
            ])

        # Also retain any untracked static objects of interest (e.g. bags / suitcases)
        for idx, d in enumerate(raw_detections):
            if idx not in used_raw_indices and d[6] in ["backpack", "suitcase", "handbag"]:
                results_out.append([
                    d[0], d[1], d[2], d[3],
                    d[4], d[5], d[6],
                    -1,
                    d[7] if len(d) > 7 else "daylight",
                ])

        return results_out

class BehaviorAnalyzer:
    """Analyzes object behaviors to detect suspicious activities"""
    
    def __init__(self):
        self.tracked_objects = {}  # Format: {id: {first_seen: timestamp, positions: [(x,y)], etc}}
        self.next_id = 0
        self.loitering_alerts = set()  # IDs of objects already alerted for loitering
    
    def update(self, detections, frame):
        """
        Update tracking for behavior analysis
        
        Args:
            detections: List of detections [x1, y1, x2, y2, conf, class_id, class_name, ...]
            frame: Current video frame
            
        Returns:
            list: Alerts triggered by behaviors
        """
        current_time = time.time()
        frame_height, frame_width = frame.shape[:2]
        alerts = []
        
        # Match detections with tracked objects or leverage existing track_id
        matched_ids = set()

        for detection in detections:
            x1, y1, x2, y2, conf, class_id, class_name = detection[:7]
            track_id = detection[7] if len(detection) > 7 and detection[7] >= 0 else None

            # Calculate center point
            center_x = (x1 + x2) // 2
            center_y = (y1 + y2) // 2

            if track_id is not None:
                obj_id = track_id
                if obj_id not in self.tracked_objects:
                    self.tracked_objects[obj_id] = {
                        'class_name': class_name,
                        'first_seen': current_time,
                        'last_seen': current_time,
                        'positions': [(center_x, center_y)],
                        'bbox': (x1, y1, x2, y2),
                        'confidence': conf
                    }
                else:
                    self.tracked_objects[obj_id]['positions'].append((center_x, center_y))
                    if len(self.tracked_objects[obj_id]['positions']) > 150:
                        self.tracked_objects[obj_id]['positions'].pop(0)
                    self.tracked_objects[obj_id]['last_seen'] = current_time
                    self.tracked_objects[obj_id]['bbox'] = (x1, y1, x2, y2)
                    self.tracked_objects[obj_id]['confidence'] = conf
                matched_ids.add(obj_id)
            else:
                # Fallback distance matching for untracked items
                matched = False
                best_match_id = None
                best_match_distance = float('inf')

                for obj_id, obj_data in self.tracked_objects.items():
                    if obj_data['class_name'] != class_name or not obj_data['positions']:
                        continue
                    last_x, last_y = obj_data['positions'][-1]
                    distance = ((last_x - center_x) ** 2 + (last_y - center_y) ** 2) ** 0.5
                    if distance < 50 and distance < best_match_distance:
                        best_match_id = obj_id
                        best_match_distance = distance
                        matched = True

                if matched:
                    obj_id = best_match_id
                    self.tracked_objects[obj_id]['positions'].append((center_x, center_y))
                    if len(self.tracked_objects[obj_id]['positions']) > 150:
                        self.tracked_objects[obj_id]['positions'].pop(0)
                    self.tracked_objects[obj_id]['last_seen'] = current_time
                    self.tracked_objects[obj_id]['bbox'] = (x1, y1, x2, y2)
                    self.tracked_objects[obj_id]['confidence'] = conf
                    matched_ids.add(obj_id)
                else:
                    self.tracked_objects[self.next_id] = {
                        'class_name': class_name,
                        'first_seen': current_time,
                        'last_seen': current_time,
                        'positions': [(center_x, center_y)],
                        'bbox': (x1, y1, x2, y2),
                        'confidence': conf
                    }
                    matched_ids.add(self.next_id)
                    self.next_id += 1

        # Remove old tracks
        ids_to_remove = []
        for obj_id in self.tracked_objects:
            if current_time - self.tracked_objects[obj_id]['last_seen'] > 5.0:  # 5 seconds timeout
                ids_to_remove.append(obj_id)

        for obj_id in ids_to_remove:
            self.tracked_objects.pop(obj_id, None)
            self.loitering_alerts.discard(obj_id)

        # Analyze behaviors
        for obj_id in matched_ids:
            obj_data = self.tracked_objects[obj_id]

            # Check for loitering
            if obj_data['class_name'] == 'person' and obj_id not in self.loitering_alerts:
                duration = current_time - obj_data['first_seen']
                time_thresh = settings.SUSPICIOUS_BEHAVIORS['loitering']['time_threshold']
                if duration > time_thresh:
                    positions = obj_data['positions']
                    if len(positions) > 8:  # Need enough points for meaningful analysis
                        x_coords = [p[0] for p in positions]
                        y_coords = [p[1] for p in positions]
                        min_x, max_x = min(x_coords), max(x_coords)
                        min_y, max_y = min(y_coords), max(y_coords)

                        area_ratio = ((max_x - min_x) * (max_y - min_y)) / max(1, (frame_width * frame_height))

                        if area_ratio < settings.SUSPICIOUS_BEHAVIORS['loitering']['area_threshold']:
                            alert = {
                                'type': 'loitering',
                                'message': f"Person loitering detected for {int(duration)}s (Track #{obj_id})",
                                'confidence': float(obj_data['confidence']),
                                'bbox': list(obj_data['bbox']),
                                'track_id': obj_id,
                                'dwell_time': duration,
                            }
                            alerts.append(alert)
                            self.loitering_alerts.add(obj_id)

            # Check for crawling behavior
            if obj_data['class_name'] == 'person':
                x1, y1, x2, y2 = obj_data['bbox']
                height = max(1, y2 - y1)
                width = max(1, x2 - x1)
                height_width_ratio = height / width

                if height_width_ratio < settings.SUSPICIOUS_BEHAVIORS['crawling']['height_ratio_threshold']:
                    alert = {
                        'type': 'crawling',
                        'message': f"Person crawling/prone posture detected (Track #{obj_id})",
                        'confidence': float(obj_data['confidence']),
                        'bbox': list(obj_data['bbox']),
                        'track_id': obj_id,
                        'critical': True,
                    }
                    alerts.append(alert)

        return alerts

class FenceTamperingDetector:
    """Detects tampering with fences and perimeter barriers"""
    
    def __init__(self):
        self.previous_frame = None
        self.fence_masks = []
        
        # Create fence region masks from settings
        for fence_region in settings.FENCE_REGIONS:
            if fence_region:
                mask = np.zeros((settings.FRAME_HEIGHT, settings.FRAME_WIDTH), dtype=np.uint8)
                points = np.array(fence_region, np.int32).reshape((-1, 1, 2))
                cv2.fillPoly(mask, [points], 255)
                self.fence_masks.append(mask)
    
    def detect(self, frame):
        """
        Detect tampering with fence regions
        
        Args:
            frame: Current video frame
            
        Returns:
            list: Fence tampering alerts if detected
        """
        if not self.fence_masks:
            return []  # No fence regions defined
        
        fh, fw = frame.shape[:2]

        # Convert frame to grayscale
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        gray = cv2.GaussianBlur(gray, (21, 21), 0)
        
        if self.previous_frame is None or self.previous_frame.shape != (fh, fw):
            self.previous_frame = gray
            return []
        
        # Calculate absolute difference between current and previous frame
        frame_delta = cv2.absdiff(self.previous_frame, gray)
        thresh = cv2.threshold(frame_delta, 25, 255, cv2.THRESH_BINARY)[1]
        
        # Dilate the thresholded image
        thresh = cv2.dilate(thresh, None, iterations=2)
        
        alerts = []
        
        # Check each fence region for significant changes
        for i, mask in enumerate(self.fence_masks):
            if mask.shape != (fh, fw):
                mask = cv2.resize(mask, (fw, fh), interpolation=cv2.INTER_NEAREST)
            # Apply mask to get changes only in fence region
            masked_thresh = cv2.bitwise_and(thresh, thresh, mask=mask)
            
            # Calculate the percentage of changed pixels in the fence region
            non_zero = cv2.countNonZero(masked_thresh)
            total = cv2.countNonZero(mask)
            change_percent = non_zero / total if total > 0 else 0
            
            if change_percent > settings.TAMPERING_SENSITIVITY:
                alert = {
                    'type': 'fence_tampering',
                    'message': f"Fence tampering detected in region {i+1}",
                    'confidence': float(change_percent),
                    'region_id': i,
                    'critical': True,
                }
                alerts.append(alert)
        
        # Update previous frame
        self.previous_frame = gray
        
        return alerts


class BorderCrossingDetector:
    """Detects unauthorized border crossings"""
    
    def __init__(self):
        # Initialize border line definitions
        self.border_lines = []
        
        # Load border lines from settings
        if hasattr(settings, 'BORDER_LINES') and settings.BORDER_LINES:
            self.border_lines = settings.BORDER_LINES
        else:
            # Default border line (horizontal line in the middle of the frame)
            self.border_lines = [
                {
                    'id': 'default',
                    'points': [(0, settings.FRAME_HEIGHT // 2), 
                              (settings.FRAME_WIDTH, settings.FRAME_HEIGHT // 2)],
                    'direction': 'both'  # 'north_to_south', 'south_to_north', or 'both'
                }
            ]
        
        # Track objects that have crossed borders
        self.tracked_objects = {}  # {object_id: {'position': (x,y), 'crossed': False, 'direction': None}}
        self.next_id = 0
        
        # Store recent crossings to avoid duplicate alerts
        self.recent_crossings = {}  # {object_id: timestamp}
        self.crossing_cooldown = 5  # seconds
        
        logger.info(f"Border crossing detector initialized with {len(self.border_lines)} border lines")
    
    def detect(self, detections, frame):
        """
        Detect border crossings based on object movements
        
        Args:
            detections: List of detections [x1, y1, x2, y2, confidence, class_id, class_name, track_id, ...]
            frame: Current video frame
            
        Returns:
            list: Border crossing alerts if detected
        """
        current_time = time.time()
        frame_height, frame_width = frame.shape[:2]
        
        # Current detections by ID for tracking
        current_detections = {}
        
        # Process each detection (focus on people, vehicles)
        for detection in detections:
            x1, y1, x2, y2, confidence, class_id, class_name = detection[:7]
            track_id = detection[7] if len(detection) > 7 and detection[7] >= 0 else None
            
            # Only track people and vehicles for border crossing
            if class_name not in ['person', 'car', 'truck', 'motorcycle', 'bicycle']:
                continue
                
            # Calculate center point of the object
            center_x = (x1 + x2) // 2
            center_y = (y1 + y2) // 2
            
            if track_id is not None:
                matched_id = track_id
                first_seen = self.tracked_objects.get(matched_id, {}).get('first_seen', current_time)
                crossed = self.tracked_objects.get(matched_id, {}).get('crossed', False)
                direction = self.tracked_objects.get(matched_id, {}).get('direction', None)
            else:
                # Try to match with existing tracked objects by distance
                matched_id = None
                for obj_id, obj_data in self.tracked_objects.items():
                    prev_x, prev_y = obj_data['position']
                    distance = ((center_x - prev_x) ** 2 + (center_y - prev_y) ** 2) ** 0.5
                    if distance < 50:
                        matched_id = obj_id
                        break
                
                if matched_id is None:
                    matched_id = self.next_id
                    self.next_id += 1
                first_seen = self.tracked_objects.get(matched_id, {}).get('first_seen', current_time)
                crossed = self.tracked_objects.get(matched_id, {}).get('crossed', False)
                direction = self.tracked_objects.get(matched_id, {}).get('direction', None)
            
            # Record current detection state
            current_detections[matched_id] = {
                'position': (center_x, center_y),
                'bbox': [x1, y1, x2, y2],
                'crossed': crossed,
                'direction': direction,
                'class': class_name,
                'confidence': confidence,
                'first_seen': first_seen,
                'last_seen': current_time,
            }
        
        # Check for border crossings
        alerts = []
        
        for obj_id, obj_data in current_detections.items():
            current_pos = obj_data['position']
            
            # Skip if this object has recently triggered an alert
            if obj_id in self.recent_crossings and current_time - self.recent_crossings[obj_id] < self.crossing_cooldown:
                continue
            
            # Get previous position if available
            prev_pos = self.tracked_objects.get(obj_id, {}).get('position')
            
            if prev_pos:
                # Check each border line
                for border in self.border_lines:
                    border_points = border['points']
                    border_direction = border.get('direction', 'both')
                    
                    # Check if the object crossed this border
                    if self._line_crossing(prev_pos, current_pos, border_points):
                        # Determine crossing direction
                        crossing_direction = self._determine_crossing_direction(prev_pos, current_pos, border_points)
                        
                        # Check if this direction should trigger an alert
                        if (border_direction == 'both' or 
                            (border_direction == 'north_to_south' and crossing_direction == 'north_to_south') or
                            (border_direction == 'south_to_north' and crossing_direction == 'south_to_north')):
                            
                            # Create alert
                            alert = {
                                'type': 'border_crossing',
                                'message': f"{obj_data['class'].capitalize()} crossed border {border.get('id', 'default')} ({crossing_direction})",
                                'confidence': 0.95,
                                'bbox': list(obj_data.get('bbox', [])),
                                'position': list(current_pos),
                                'border_id': border.get('id', 'default'),
                                'direction': crossing_direction,
                                'object_class': obj_data['class'],
                                'track_id': obj_id,
                                'critical': True
                            }
                            alerts.append(alert)
                            
                            # Update object status
                            current_detections[obj_id]['crossed'] = True
                            current_detections[obj_id]['direction'] = crossing_direction
                            
                            # Add to recent crossings
                            self.recent_crossings[obj_id] = current_time
        
        # Update tracked objects
        self.tracked_objects = current_detections
        
        # Clean up old tracked objects
        self._cleanup_old_tracks(current_time)
        
        return alerts
    
    def _line_crossing(self, p1, p2, line):
        """Check if a moving object (from p1 to p2) crosses a line"""
        x1, y1 = p1
        x2, y2 = p2
        line_x1, line_y1 = line[0]
        line_x2, line_y2 = line[1]
        
        # Line intersection formula
        def ccw(a, b, c):
            return (c[1] - a[1]) * (b[0] - a[0]) > (b[1] - a[1]) * (c[0] - a[0])
        
        a = (x1, y1)
        b = (x2, y2)
        c = (line_x1, line_y1)
        d = (line_x2, line_y2)
        
        return ccw(a, c, d) != ccw(b, c, d) and ccw(a, b, c) != ccw(a, b, d)
    
    def _determine_crossing_direction(self, p1, p2, line):
        """Determine the direction of crossing (north_to_south or south_to_north)"""
        x1, y1 = p1
        x2, y2 = p2
        line_x1, line_y1 = line[0]
        line_x2, line_y2 = line[1]
        
        # For a horizontal line
        if abs(line_y1 - line_y2) < abs(line_x1 - line_x2):
            if y2 > y1:
                return "north_to_south"
            else:
                return "south_to_north"
        # For a vertical line
        else:
            if x2 > x1:
                return "west_to_east"
            else:
                return "east_to_west"
    
    def _cleanup_old_tracks(self, current_time, max_age=10):
        """Remove tracks that haven't been updated recently"""
        ids_to_remove = []
        
        for obj_id, obj_data in self.tracked_objects.items():
            if current_time - obj_data.get('first_seen', 0) > max_age:
                ids_to_remove.append(obj_id)
        
        for obj_id in ids_to_remove:
            del self.tracked_objects[obj_id]
        
        # Also clean up recent crossings
        crossings_to_remove = []
        for obj_id, timestamp in self.recent_crossings.items():
            if current_time - timestamp > self.crossing_cooldown:
                crossings_to_remove.append(obj_id)
        
        for obj_id in crossings_to_remove:
            del self.recent_crossings[obj_id]
