# collect_faces.py
"""
Capture face images for biometric evaluation.
Run once per person. Images are saved to dataset/<name>/.
"""

import os
import cv2
import time


def collect(name, num_images=20):
    folder = os.path.join("dataset", name)
    os.makedirs(folder, exist_ok=True)

    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
    if not cap.isOpened():
        print("Could not open webcam.")
        return

    print(f"Capturing {num_images} images for '{name}'.")
    print("Press SPACE to capture, or 'q' to quit.")
    print("Vary your angle, distance, and expression slightly between shots.\n")

    count = 0
    while count < num_images:
        ret, frame = cap.read()
        if not ret:
            break

        cv2.putText(frame, f"{name}: {count}/{num_images}",
                    (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
        cv2.putText(frame, "SPACE to capture, Q to quit",
                    (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 1)
        cv2.imshow("Dataset collection", frame)

        key = cv2.waitKey(1) & 0xFF
        if key == ord(' '):
            path = os.path.join(folder, f"{count:03d}.jpg")
            cv2.imwrite(path, frame)
            count += 1
            print(f"Captured {count}/{num_images}")
            time.sleep(0.3)
        elif key == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()
    print(f"\nSaved {count} images to {folder}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python collect_faces.py <name>")
        print("Example: python collect_faces.py alice")
        sys.exit(1)
    collect(sys.argv[1], num_images=20)