# AI-Powered Border Surveillance System

An autonomous surveillance system that detects, tracks, and verifies threats in real-time using multimodal AI. This system provides comprehensive monitoring of border areas with intelligent threat detection capabilities.

## Features

- **Live Reconnaissance**: Real-time YOLOv8 + ByteTrack perimeter surveillance (35–50 FPS on Tensor Cores)
- **Perimeter & Behavior Analytics**: Detects intrusion, loitering, crawling, fence tampering, and border crossings
- **Blockchain Evidence Ledger**: SIH theme — cryptographic SHA-256 tamper-evident ledger and immutable audit trail
- **Behavioral Baseline Engine**: Innovation 1 — per-hour adaptive statistical baseline and anomaly scoring with feedback loop
- **Bandwidth-Aware Sync Layer**: Innovation 2 — two-phase metadata-first upload queue for remote low-bandwidth outposts
- **AI Investigation Assistant**: Innovation 3 — Gemini 3.7 Flash answering strictly from local database context with auto-report drafting
- **Interactive Command & Control Web Platform**: Tactical Tailwind CSS HUD with zero external cloud dependencies

## Tactical Command & Control (C2) Modules

The web dashboard provides 6 purpose-built, live-data command modules:
1. **Live Reconnaissance**: Real-time AI video stream with bounding boxes, sector threat overlays, and source selector.
2. **Threat Forensics Log**: Comprehensive database archive of alerts with optical evidence snapshots and risk scores.
3. **Restricted Zones**: Interactive polygon perimeter definition with instantaneous boundary enforcement.
4. **Baseline Engine**: 24-hour behavioral baselines, Z-score thresholds, and false-positive recalibration.
5. **AI Assistant**: Natural-language intelligence Q&A and one-click five-section forensic incident report drafting.
6. **Blockchain Ledger**: Cryptographic verification of evidence hashes and immutable operator audit logs.

## Project Structure

```
Border-Surveillance-System/
├── run_web.py         # Primary Application (Tactical Web C2 Platform)
├── src/               # Source code for surveillance modules
│   ├── dashboard_api.py # FastAPI backend & telemetry endpoints
│   ├── detection.py   # Object detection and behavior analysis modules
│   ├── visualization.py # Visualization and GIS mapping utilities
│   └── web_server.py  # ASGI server module
├── web/               # Tactical Web Dashboard (Tailwind CSS HUD)
├── database/          # SQLAlchemy models and SQLite storage
├── baseline_engine/   # Innovation 1: Adaptive behavioral baseline
├── sync_layer/        # Innovation 2: Bandwidth-aware sync queue
├── assistant/         # Innovation 3: Grounded AI Investigation Assistant
├── blockchain/        # SIH Theme: Tamper-proof evidence ledger
├── models/            # Pre-trained AI models
├── config/            # Configuration files
├── utils/             # Utility functions and helpers
├── output/            # Snapshots and detection maps
├── requirements.txt   # Dependencies
└── .env               # Environment configuration
```

## Requirements

The system requires the following major dependencies:
- Python 3.8+
- PyTorch 1.9.0+
- OpenCV 4.5.0+
- Ultralytics (YOLOv8)
- FastAPI / Uvicorn (for dashboard backend)
- SQLAlchemy (for evidence database)
- Additional dependencies listed in `requirements.txt`

## Running the System

### Tactical Web Command & Control (C2) — Primary Application

To launch the full tactical command and control web platform:

```bash
python run_web.py
```

Optional CLI flags:
- `--host`: Host interface to bind (default: `0.0.0.0`)
- `--port`: Port to listen on (default: `8000`)
- `--source`: Video source (`0` for webcam, or path to video file)
- `--no-browser`: Run in headless mode without automatically launching a browser window

This automatically starts the FastAPI server and opens `http://localhost:8000` in your default web browser, featuring:
- **Reconnaissance HUD**: High-speed real-time video stream (webcam or sample video) with YOLOv8 inference and ByteTrack.
- **Threat Forensics**: Incident logs and forensic snapshot evidence viewer.
- **Restricted Zones**: Dynamic polygon geofencing and intrusion detection.
- **Adaptive Baseline Engine**: Behavioral activity baselines with automatic false-alarm recalibration.
- **AI Investigation Assistant**: Natural-language Q&A grounded strictly in surveillance logs.
- **Blockchain Evidence Ledger**: Cryptographic hash verifier and tamper-evident audit trail.

Example running with custom source and headless mode:
```bash
python run_web.py --source gettyimages-1215957003-640_adpp.mp4 --port 8000
```

## Dashboard Access

The command center dashboard is accessible in your web browser at:
```
http://localhost:8000
```

## Deployment

The system is designed to run on edge devices such as NVIDIA Jetson or similar hardware with GPU capabilities for real-time inference. For production deployment, consider:

- Setting up as a system service for automatic startup
- Configuring remote monitoring capabilities
- Implementing data retention policies for captured footage

## License

MIT 