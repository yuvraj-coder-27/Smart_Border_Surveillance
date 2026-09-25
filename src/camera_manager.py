"""
src/camera_manager.py
=====================
Multi-Camera & Edge Node Deployment Manager.

Manages edge camera nodes, stream switches, edge hardware health metrics,
and distributed multi-camera topology.
"""

import os
import time
import psutil
from typing import Dict, List, Any, Optional

import torch
from utils.logger import logger
from config import settings

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SAMPLE_VIDEO_1 = getattr(settings, "SAMPLE_VIDEO_1", os.path.join(_PROJECT_ROOT, "gettyimages-1215957003-640_adpp.mp4"))
_SAMPLE_VIDEO_2 = getattr(settings, "SAMPLE_VIDEO_2", os.path.join(_PROJECT_ROOT, "15690486_1920_1080_25fps.mp4"))
_SAMPLE_VIDEO = _SAMPLE_VIDEO_1

DEFAULT_CAMERAS = {
    "cam_0": {
        "id": "cam_0",
        "name": "Zero-Line North Outpost",
        "sector": "Sector Alpha (Frontier)",
        "location": "Post 14-A (32.414° N, 74.891° E)",
        "source": _SAMPLE_VIDEO_1 if os.path.exists(_SAMPLE_VIDEO_1) else 0,
        "status": "ONLINE",
        "resolution": "768x432",
        "target_fps": 30,
        "is_active": True,
    },
    "cam_1": {
        "id": "cam_1",
        "name": "Sector B Perimeter Crossing",
        "sector": "Sector Bravo (Fencing & Transit)",
        "location": "Post 18-C (32.428° N, 74.905° E)",
        "source": _SAMPLE_VIDEO_2 if os.path.exists(_SAMPLE_VIDEO_2) else (_SAMPLE_VIDEO_1 if os.path.exists(_SAMPLE_VIDEO_1) else 0),
        "status": "ONLINE",
        "resolution": "1920x1080",
        "target_fps": 25,
        "is_active": False,
    },
    "cam_2": {
        "id": "cam_2",
        "name": "Riverine Crossing Checkpoint",
        "sector": "Sector Charlie (Waterway)",
        "location": "River Checkpoint 3 (32.451° N, 74.872° E)",
        "source": _SAMPLE_VIDEO_1 if os.path.exists(_SAMPLE_VIDEO_1) else 0,
        "status": "STANDBY",
        "resolution": "640x480",
        "target_fps": 25,
        "is_active": False,
    },
    "cam_3": {
        "id": "cam_3",
        "name": "Ammunition Depot Gate (HD Optic)",
        "sector": "Sector Delta (Support Facility)",
        "location": "Depot Gate North (32.399° N, 74.920° E)",
        "source": _SAMPLE_VIDEO_2 if os.path.exists(_SAMPLE_VIDEO_2) else (_SAMPLE_VIDEO_1 if os.path.exists(_SAMPLE_VIDEO_1) else 0),
        "status": "ONLINE",
        "resolution": "1920x1080",
        "target_fps": 25,
        "is_active": False,
    },
}


class CameraManager:
    """Manages multi-camera network and edge compute hardware metrics."""

    def __init__(self, engine=None):
        self.cameras = dict(DEFAULT_CAMERAS)
        self.active_camera_id = "cam_0"
        self.engine = engine
        self._boot_time = time.time()
        logger.info(f"CameraManager initialized with {len(self.cameras)} registered camera nodes.")

    def set_engine(self, engine):
        self.engine = engine

    def get_cameras(self) -> List[Dict[str, Any]]:
        """List all cameras with active status and live telemetry."""
        result = []
        for cam_id, cam in self.cameras.items():
            entry = dict(cam)
            entry["is_active"] = (cam_id == self.active_camera_id)
            if self.engine and entry["is_active"]:
                entry["current_fps"] = round(getattr(self.engine, "fps", 30.0), 1)
            else:
                entry["current_fps"] = entry.get("target_fps", 30)
            result.append(entry)
        return result

    def get_camera(self, camera_id: str) -> Optional[Dict[str, Any]]:
        return self.cameras.get(camera_id)

    def get_active_camera_id(self) -> str:
        return self.active_camera_id

    def switch_camera(self, camera_id: str) -> Dict[str, Any]:
        """Switch active camera stream on the surveillance engine."""
        if camera_id not in self.cameras:
            return {"status": "error", "message": f"Camera '{camera_id}' not found."}

        self.active_camera_id = camera_id
        target = self.cameras[camera_id]

        for cid in self.cameras:
            self.cameras[cid]["is_active"] = (cid == camera_id)

        if self.engine:
            self.engine.camera_id = camera_id
            self.engine.switch_source(target["source"])

        logger.info(f"Switched surveillance focus to Camera [{camera_id}] - {target['name']}")
        return {
            "status": "success",
            "camera_id": camera_id,
            "active_camera_id": camera_id,
            "camera_name": target["name"],
            "camera": target,
            "sector": target["sector"],
        }

    def get_edge_telemetry(self) -> Dict[str, Any]:
        """Collect edge compute hardware health, memory, and acceleration stats."""
        cpu_pct = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        gpu_info = {
            "available": torch.cuda.is_available(),
            "device_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU",
            "allocated_mb": round(torch.cuda.memory_allocated(0) / (1024 * 1024), 1) if torch.cuda.is_available() else 0,
            "reserved_mb": round(torch.cuda.memory_reserved(0) / (1024 * 1024), 1) if torch.cuda.is_available() else 0,
        }

        uptime_seconds = int(time.time() - self._boot_time)

        return {
            "edge_node_id": "EDGE-TACTICAL-ALPHA-01",
            "location": "North Outpost Forward Unit",
            "status": "HEALTHY",
            "uptime_seconds": uptime_seconds,
            "cpu_percent": cpu_pct,
            "ram_used_gb": round(mem.used / (1024**3), 2),
            "ram_total_gb": round(mem.total / (1024**3), 2),
            "ram_percent": mem.percent,
            "disk_percent": disk.percent,
            "gpu": gpu_info,
            "active_camera": self.active_camera_id,
            "total_cameras": len(self.cameras),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }


# Global singleton instance
camera_manager = CameraManager()
