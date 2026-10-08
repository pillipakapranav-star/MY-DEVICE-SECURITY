"""
Aegis Sentinel - Camera & Burst Capture Service
Handles webcam streaming, rapid multi-shot burst capture, and incident/time labels.
"""

import time
import datetime
from pathlib import Path
from typing import List, Optional, Tuple
import cv2
from config import INTRUDER_DIR


class CameraService:
    """Manages video capture hardware and rapid burst intruder photography."""

    def __init__(self, camera_index: int = 0):
        self.camera_index = camera_index
        self._cap: Optional[cv2.VideoCapture] = None

    def open_camera(self) -> bool:
        """Open camera device if not already open."""
        if self._cap is not None and self._cap.isOpened():
            return True
        self._cap = cv2.VideoCapture(self.camera_index, cv2.CAP_DSHOW)
        if not self._cap.isOpened():
            # Fallback without CAP_DSHOW
            self._cap = cv2.VideoCapture(self.camera_index)
        if self._cap.isOpened():
            self._cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            self._cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
            return True
        return False

    def close_camera(self):
        """Release camera resource."""
        if self._cap is not None:
            try:
                self._cap.release()
            except Exception:
                pass
            self._cap = None

    def read_frame(self) -> Tuple[bool, Optional[any]]:
        """Read a single frame from the camera."""
        if not self.open_camera():
            return False, None
        ret, frame = self._cap.read()
        return ret, frame

    def capture_burst_images(
        self,
        count: int = 5,
        interval_sec: float = 0.2,
        location_meta: Optional[dict] = None
    ) -> List[Path]:
        """
        Capture rapid burst of intruder images (default: 5 photos @ 0.2s).
        Overlays incident and time labels, plus an approximate IP area when available.
        Saves each frame to the captured_intruders/ folder.
        """
        saved_paths: List[Path] = []
        cap_was_closed = False

        if self._cap is None or not self._cap.isOpened():
            cap_was_closed = True
            if not self.open_camera():
                print("[CameraService] [ERROR] Could not open camera for burst capture.")
                return saved_paths

        # Allow auto-exposure & sensor to stabilize
        for _ in range(3):
            self._cap.read()
            time.sleep(0.05)

        session_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        print(f"[CameraService] Initiating burst capture: {count} frames @ {interval_sec}s interval...")

        lat = location_meta.get("lat") if location_meta else None
        lon = location_meta.get("lon") if location_meta else None
        city = location_meta.get("city", "Unknown") if location_meta else "Unknown"

        for i in range(1, count + 1):
            ret, frame = self._cap.read()
            if ret and frame is not None:
                # Add forensic watermark
                watermarked = frame.copy()
                now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                alert_text = f"ALERT: UNAUTHORIZED ATTEMPT | Frame #{i}/{count}"
                coords = f"approx IP {lat:.4f},{lon:.4f}" if lat is not None and lon is not None else "location unavailable"
                geo_text = f"AREA: {city} ({coords}) | TIME: {now_str}"

                # Draw top bar banner
                cv2.rectangle(watermarked, (0, 0), (640, 42), (0, 0, 180), -1)
                cv2.putText(
                    watermarked, alert_text, (10, 18),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.45, (255, 255, 255), 1, cv2.LINE_AA
                )
                cv2.putText(
                    watermarked, geo_text, (10, 35),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.40, (220, 220, 220), 1, cv2.LINE_AA
                )

                file_path = INTRUDER_DIR / f"intruder_{session_id}_shot_{i}.jpg"
                cv2.imwrite(str(file_path), watermarked, [int(cv2.IMWRITE_JPEG_QUALITY), 92])
                saved_paths.append(file_path)
                print(f"[CameraService] Saved burst frame {i}/{count}: {file_path.name}")
            else:
                print(f"[CameraService] [WARNING] Failed to capture burst frame {i}/{count}")

            if i < count:
                time.sleep(interval_sec)

        if cap_was_closed:
            self.close_camera()

        print(f"[CameraService] Burst capture completed. {len(saved_paths)} images preserved.")
        return saved_paths
