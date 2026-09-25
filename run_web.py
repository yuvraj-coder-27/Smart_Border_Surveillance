import os
import sys
import time
import webbrowser
import threading
import argparse


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import uvicorn
from config import settings

def parse_args():
    parser = argparse.ArgumentParser(description="Launch Border Surveillance Web Command Center")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind (default: 0.0.0.0)")
    parser.add_argument("--port", default=8000, type=int, help="Port to listen on (default: 8000)")
    parser.add_argument("--source", default=None, help="Video source (0 for webcam, or path to video file)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")
    return parser.parse_args()

def open_browser(url):
    time.sleep(1.5)
    print(f"\n[INFO] Opening Tactical Command Center at {url} ...\n")
    webbrowser.open(url)

def main():
    args = parse_args()
    
    if args.source:
        if args.source in ["sample_2", "sample2", "2"]:
            sample2_path = os.path.join(PROJECT_ROOT, "15690486_1920_1080_25fps.mp4")
            settings.VIDEO_SOURCE = sample2_path if os.path.exists(sample2_path) else args.source
        elif args.source in ["sample_1", "sample1", "1", "sample"]:
            sample1_path = os.path.join(PROJECT_ROOT, "gettyimages-1215957003-640_adpp.mp4")
            settings.VIDEO_SOURCE = sample1_path if os.path.exists(sample1_path) else args.source
        else:
            settings.VIDEO_SOURCE = args.source
    elif not hasattr(settings, 'VIDEO_SOURCE') or str(settings.VIDEO_SOURCE).strip() in ['0', '', 'None']:
        sample_path = os.path.join(PROJECT_ROOT, "gettyimages-1215957003-640_adpp.mp4")
        if os.path.exists(sample_path):
            settings.VIDEO_SOURCE = sample_path

    from src.web_server import app, engine
    if engine and hasattr(settings, 'VIDEO_SOURCE'):
        engine.source = settings.VIDEO_SOURCE

    display_host = "localhost" if args.host in ["0.0.0.0", "127.0.0.1"] else args.host
    url = f"http://{display_host}:{args.port}"

    print("=" * 70)
    print("     BORDER SURVEILLANCE SYSTEM - TACTICAL COMMAND & CONTROL (C2)")
    print("=" * 70)
    print(f" [*] Web Server running at:  {url}")
    print(f" [*] Real-time Alerts:       WebSocket enabled at ws://{display_host}:{args.port}/ws")
    print(f" [*] Video Input Source:     {settings.VIDEO_SOURCE}")
    print(f" [*] Architecture:           FastAPI + YOLOv8 + Tailwind Tactical HUD")
    print("=" * 70)
    print(" Press Ctrl+C to terminate the surveillance system.\n")

    if not args.no_browser:
        browser_thread = threading.Thread(target=open_browser, args=(url,), daemon=True)
        browser_thread.start()

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")

if __name__ == "__main__":
    main()
