"""
Aegis Sentinel - Face Recognition & Biometric Sentry Service
Enforces Owner-Only presence access control using OpenCV LBPH Face Recognizer.
Detects authorized system owner vs unknown intruder persons in real-time.
"""

import os
import json
import time
from pathlib import Path
from typing import Tuple, List, Optional
import cv2
import numpy as np
from config import FACE_MODEL_FILE, FACE_LABELS_FILE, FACE_DATASET_DIR, CASCADE_FACE_FILE


class FaceRecognitionService:
    """Manages biometric owner enrollment and real-time intruder face detection."""

    def __init__(self, confidence_threshold: float = 70.0):
        self.confidence_threshold = confidence_threshold
        cascade_path = str(CASCADE_FACE_FILE) if CASCADE_FACE_FILE.exists() else (cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
        self.face_cascade = cv2.CascadeClassifier(cascade_path)
        self.recognizer = cv2.face.LBPHFaceRecognizer_create(radius=1, neighbors=8, grid_x=8, grid_y=8)
        self.is_trained = False
        self.owner_label_id = 1
        self.owner_name = "Authorized Owner"
        self._load_trained_model()

    def _load_trained_model(self) -> bool:
        """Load trained LBPH model and label mapping if available."""
        if FACE_MODEL_FILE.exists() and FACE_LABELS_FILE.exists():
            try:
                self.recognizer.read(str(FACE_MODEL_FILE))
                with open(FACE_LABELS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.owner_name = data.get("owner_name", "Authorized Owner")
                    self.owner_label_id = data.get("label_id", 1)
                self.is_trained = True
                print(f"[FaceRecognition] Loaded biometric model for: '{self.owner_name}'")
                return True
            except Exception as e:
                print(f"[FaceRecognition] Error loading model: {e}")
        self.is_trained = False
        return False

    def detect_faces(self, frame: np.ndarray) -> List[Tuple[int, int, int, int]]:
        """Detect all face bounding boxes (x, y, w, h) in a frame."""
        if frame is None:
            return []
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        gray = cv2.equalizeHist(gray)
        faces = self.face_cascade.detectMultiScale(
            gray,
            scaleFactor=1.15,
            minNeighbors=5,
            minSize=(80, 80)
        )
        return list(faces)

    def enroll_owner_samples(self, frames_list: List[np.ndarray], owner_name: str = "Authorized Owner") -> bool:
        """
        Train the LBPH recognizer from a list of captured owner face frames.
        Saves dataset, trains model, and serializes to disk.
        """
        training_faces = []
        labels = []
        sample_count = 0

        # Clear previous samples in dataset dir
        for p in FACE_DATASET_DIR.glob("*.jpg"):
            try:
                p.unlink()
            except Exception:
                pass

        for frame in frames_list:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            gray = cv2.equalizeHist(gray)
            detected = self.face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=4, minSize=(80, 80))
            for (x, y, w, h) in detected:
                face_crop = gray[y:y + h, x:x + w]
                face_resized = cv2.resize(face_crop, (180, 180))
                training_faces.append(face_resized)
                labels.append(self.owner_label_id)
                sample_count += 1

                # Save sample image
                sample_file = FACE_DATASET_DIR / f"owner_sample_{sample_count}.jpg"
                cv2.imwrite(str(sample_file), face_resized)
                break  # Take primary face in frame

        if len(training_faces) < 5:
            print(f"[FaceRecognition] Insufficient face samples collected ({len(training_faces)}/5 minimum).")
            return False

        print(f"[FaceRecognition] Training LBPH model on {len(training_faces)} face samples...")
        self.recognizer.train(training_faces, np.array(labels))
        self.recognizer.write(str(FACE_MODEL_FILE))

        # Save label metadata
        label_data = {
            "owner_name": owner_name,
            "label_id": self.owner_label_id,
            "trained_samples": len(training_faces),
            "updated_at": time.time()
        }
        with open(FACE_LABELS_FILE, "w", encoding="utf-8") as f:
            json.dump(label_data, f, indent=4)

        self.owner_name = owner_name
        self.is_trained = True
        print(f"[FaceRecognition] [SUCCESS] Owner model successfully trained and saved for '{owner_name}'.")
        return True

    def process_frame(self, frame: np.ndarray) -> dict:
        """
        Process a single camera frame for Case 2 Sentry Mode.
        Identifies whether detected faces are the Authorized Owner or Unknown Person.
        Overlays cyber-security HUD bounding boxes.
        """
        result = {
            "owner_detected": False,
            "unknown_detected": False,
            "face_count": 0,
            "annotated_frame": frame.copy() if frame is not None else None,
            "faces_info": []
        }

        if frame is None:
            return result

        annotated = result["annotated_frame"]
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        gray = cv2.equalizeHist(gray)
        faces = self.face_cascade.detectMultiScale(
            gray,
            scaleFactor=1.15,
            minNeighbors=5,
            minSize=(80, 80)
        )
        result["face_count"] = len(faces)

        if len(faces) == 0:
            # Draw HUD status top bar
            cv2.rectangle(annotated, (0, 0), (640, 36), (30, 30, 30), -1)
            cv2.putText(
                annotated, "SENTRY SCANNING - NO HUMAN FACE IN VIEW",
                (12, 24), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (160, 160, 160), 1, cv2.LINE_AA
            )
            return result

        for (x, y, w, h) in faces:
            face_roi = gray[y:y + h, x:x + w]
            face_resized = cv2.resize(face_roi, (180, 180))

            is_owner = False
            confidence_dist = 999.0

            if self.is_trained:
                try:
                    label, confidence_dist = self.recognizer.predict(face_resized)
                    # In LBPH, lower distance = better match
                    if label == self.owner_label_id and confidence_dist < self.confidence_threshold:
                        is_owner = True
                except Exception as e:
                    print(f"[FaceRecognition] Prediction error: {e}")

            if is_owner:
                result["owner_detected"] = True
                box_color = (0, 220, 0)  # Bright Green
                match_pct = max(0, min(100, int(100 - (confidence_dist / 1.5))))
                tag = f"AUTHORIZED OWNER: {self.owner_name} [{match_pct}%]"
            else:
                result["unknown_detected"] = True
                box_color = (0, 0, 255)  # Bright Red
                tag = "UNKNOWN PERSON DETECTED - UNAUTHORIZED"

            result["faces_info"].append({
                "bbox": (int(x), int(y), int(w), int(h)),
                "is_owner": is_owner,
                "confidence_dist": float(confidence_dist),
                "tag": tag
            })

            # Draw futuristic corner brackets and label
            cv2.rectangle(annotated, (x, y), (x + w, y + h), box_color, 2)
            cv2.rectangle(annotated, (x, y - 28), (x + w, y), box_color, -1)
            cv2.putText(
                annotated, tag, (x + 6, y - 8),
                cv2.FONT_HERSHEY_SIMPLEX, 0.42, (255, 255, 255), 1, cv2.LINE_AA
            )

        # Top banner summary
        top_banner_bg = (0, 160, 0) if (result["owner_detected"] and not result["unknown_detected"]) else (0, 0, 180)
        top_banner_text = (
            f"OWNER PRESENT: {self.owner_name}"
            if (result["owner_detected"] and not result["unknown_detected"])
            else "CRITICAL ALERT: UNAUTHORIZED / UNKNOWN PERSON DETECTED!"
        )
        cv2.rectangle(annotated, (0, 0), (640, 36), top_banner_bg, -1)
        cv2.putText(
            annotated, top_banner_text, (12, 24),
            cv2.FONT_HERSHEY_SIMPLEX, 0.52, (255, 255, 255), 2, cv2.LINE_AA
        )

        return result
