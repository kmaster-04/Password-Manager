# biometric_auth.py
"""
Webcam-based face recognition for vault unlock.

Two barriers:
  1. Distance check — the live encoding must be within FACE_MATCH_TOLERANCE
     of the reference encoding stored at enrollment.
  2. Fuzzy extractor — the wrapping key is derived from the live encoding,
     so even an impostor who passes the distance check cannot decrypt the
     wrapped master password.

Both barriers must pass for the vault to unlock.
"""

import os
import json
import base64
import time
import numpy as np
import cv2
import dlib
import face_recognition
from scipy.spatial import distance as dist
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import face_recognition_models
from fuzzy_extractor import BiometricFuzzyExtractor


def _find_landmark_model():
    base = os.path.dirname(os.path.abspath(face_recognition_models.__file__))
    for path in [
        os.path.join(base, "shape_predictor_68_face_landmarks.dat"),
        os.path.join(base, "models", "shape_predictor_68_face_landmarks.dat"),
    ]:
        if os.path.exists(path):
            return path
    try:
        return face_recognition_models.pose_predictor_model_location()
    except Exception:
        return None


LANDMARK_MODEL_PATH = _find_landmark_model()

EYE_AR_THRESH = 0.25
EYE_AR_CONSEC_FRAMES = 2
REQUIRED_BLINKS = 2
FACE_MATCH_TOLERANCE = 0.45     # tightened from 0.5 for extra margin
BIOMETRIC_FILE_SUFFIX = ".bio"
ENROLLMENT_SAMPLES = 5


def _load_dlib_models():
    if LANDMARK_MODEL_PATH is None:
        raise RuntimeError("Could not locate shape_predictor_68_face_landmarks.dat.")
    detector = dlib.get_frontal_face_detector()
    predictor = dlib.shape_predictor(LANDMARK_MODEL_PATH)
    return detector, predictor


_DETECTOR, _PREDICTOR = _load_dlib_models()
_EXTRACTOR = BiometricFuzzyExtractor()


def eye_aspect_ratio(eye_points):
    A = dist.euclidean(eye_points[1], eye_points[5])
    B = dist.euclidean(eye_points[2], eye_points[4])
    C = dist.euclidean(eye_points[0], eye_points[3])
    return (A + B) / (2.0 * C)


def _get_eye_points(shape):
    points = np.array([[shape.part(i).x, shape.part(i).y] for i in range(68)])
    return points[36:42], points[42:48]


def _run_capture(prompt, num_samples=1, timeout=30):
    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
    if not cap.isOpened():
        print("Error: could not open webcam.")
        return None

    print(prompt)
    print("Press 'q' to cancel.")

    blink_counter = 0
    total_blinks = 0
    samples = []
    last_sample_time = 0
    start_time = time.time()

    try:
        while True:
            if time.time() - start_time > timeout:
                print("Timed out.")
                return None

            ret, frame = cap.read()
            if not ret:
                return None

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = _DETECTOR(gray, 0)

            for face in faces:
                shape = _PREDICTOR(gray, face)
                left_eye, right_eye = _get_eye_points(shape)
                ear = (eye_aspect_ratio(left_eye) + eye_aspect_ratio(right_eye)) / 2.0

                cv2.drawContours(frame, [cv2.convexHull(left_eye)], -1, (0, 255, 0), 1)
                cv2.drawContours(frame, [cv2.convexHull(right_eye)], -1, (0, 255, 0), 1)

                if ear < EYE_AR_THRESH:
                    blink_counter += 1
                else:
                    if blink_counter >= EYE_AR_CONSEC_FRAMES:
                        total_blinks += 1
                    blink_counter = 0

                if total_blinks >= REQUIRED_BLINKS:
                    now = time.time()
                    if now - last_sample_time > 0.3:
                        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                        locations = face_recognition.face_locations(rgb)
                        if len(locations) == 1:
                            enc = face_recognition.face_encodings(rgb, locations)
                            if enc:
                                samples.append(enc[0])
                                last_sample_time = now
                                if len(samples) >= num_samples:
                                    return samples

            status = f"Blinks: {total_blinks}/{REQUIRED_BLINKS}"
            if samples:
                status += f"  Samples: {len(samples)}/{num_samples}"
            cv2.putText(frame, status, (10, 30),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
            cv2.imshow("Face capture - blink to verify", frame)

            if cv2.waitKey(1) & 0xFF == ord('q'):
                return None
    finally:
        cap.release()
        cv2.destroyAllWindows()


def enroll_face(num_samples=ENROLLMENT_SAMPLES):
    return _run_capture(
        prompt=f"Enrollment: blink {REQUIRED_BLINKS} times, then hold still "
               f"for {num_samples} samples.",
        num_samples=num_samples,
    )


def capture_one():
    samples = _run_capture(
        prompt=f"Authentication: blink {REQUIRED_BLINKS} times.",
        num_samples=1,
    )
    return samples[0] if samples else None


def biometric_file_path(vault_path):
    return vault_path + BIOMETRIC_FILE_SUFFIX


def enroll_biometric(vault_path, master_password):
    samples = enroll_face()
    if not samples:
        print("Enrollment failed: no samples captured.")
        return False

    print(f"Captured {len(samples)} samples. Building enrollment record...")
    enrollment, key = _EXTRACTOR.enroll(samples)

    # Reference encoding = mean of samples (used for the distance check)
    reference = np.mean(np.array(samples), axis=0)

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, master_password.encode("utf-8"), None)

    record = {
        "version": 3,
        "reference_encoding": reference.tolist(),
        "indices": enrollment["indices"],
        "sketch": enrollment["sketch"],
        "parity": enrollment["parity"],
        "message_len": enrollment["message_len"],
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }

    with open(biometric_file_path(vault_path), "w") as f:
        json.dump(record, f, indent=2)

    return True


def unlock_biometric(vault_path, tolerance=FACE_MATCH_TOLERANCE,
                     skip_distance_check=False):
    """
    Authenticate via webcam.

    Barrier 1: distance check against reference_encoding.
    Barrier 2: fuzzy extractor reconstructs the wrapping key from the
               live encoding.

    Both must pass.

    skip_distance_check is for DEMONSTRATION ONLY. It lets you show that
    the fuzzy extractor alone still rejects an impostor.
    """
    path = biometric_file_path(vault_path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"No biometric enrollment found at {path}")

    with open(path, "r") as f:
        record = json.load(f)

    if record.get("version") != 3:
        raise ValueError(
            "Enrollment uses an older format. "
            "Run enroll-biometric again to upgrade."
        )

    reference = np.asarray(record["reference_encoding"], dtype=np.float64)

    live = capture_one()
    if live is None:
        raise ValueError("No face captured.")

    # ---- BARRIER 1: distance check ----
    if not skip_distance_check:
        distance = float(face_recognition.face_distance([reference], live)[0])
        print(f"Distance to reference: {distance:.4f} (threshold {tolerance:.2f})")
        if distance > tolerance:
            raise ValueError(
                f"Face does not match the enrolled user "
                f"(distance {distance:.4f} > {tolerance:.2f})."
            )
    else:
        print("Distance check SKIPPED (demonstration mode).")

    # ---- BARRIER 2: fuzzy extractor ----
    enrollment = {
        "indices": record["indices"],
        "sketch": record["sketch"],
        "parity": record["parity"],
        "message_len": record["message_len"],
    }

    key = _EXTRACTOR.reconstruct(live, enrollment, verbose=True)
    if key is None:
        raise ValueError(
            "Fuzzy extractor rejected the input "
            "(error correction failed)."
        )

    nonce = base64.b64decode(record["nonce"])
    ciphertext = base64.b64decode(record["ciphertext"])

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed — wrong wrapping key.")

    return plaintext.decode("utf-8")