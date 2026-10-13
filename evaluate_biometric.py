# evaluate_biometric.py
"""
Evaluate the biometric verification system using standard ML metrics.

Treats verification as binary classification:
  Positive (1) = genuine attempts (enrolled user)
  Negative (0) = impostor attempts (everyone else)

Computes FAR, FRR, EER, ROC curve, and AUC.
"""

import os
import numpy as np
import face_recognition
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc


DATASET_DIR = "dataset"
ENROLLED_PERSON = "admin"   # <-- CHANGE THIS to your own name


def load_embeddings(person):
    """Compute face encodings for every image of a person."""
    folder = os.path.join(DATASET_DIR, person)
    encodings = []
    for filename in sorted(os.listdir(folder)):
        if not filename.lower().endswith((".jpg", ".png")):
            continue
        path = os.path.join(folder, filename)
        image = face_recognition.load_image_file(path)
        locations = face_recognition.face_locations(image)
        if len(locations) != 1:
            continue
        enc = face_recognition.face_encodings(image, locations)
        if enc:
            encodings.append(enc[0])
    return np.array(encodings)


def main():
    people = sorted(os.listdir(DATASET_DIR))
    if ENROLLED_PERSON not in people:
        print(f"Enrolled person '{ENROLLED_PERSON}' not found in {DATASET_DIR}")
        return

    print("Loading embeddings...")
    all_encodings = {p: load_embeddings(p) for p in people}
    for p, e in all_encodings.items():
        print(f"  {p}: {len(e)} encodings")

    enrolled = all_encodings[ENROLLED_PERSON]
    if len(enrolled) < 2:
        print("Not enough images of the enrolled person.")
        return

    # First image is the reference (what would be stored at enrollment)
    reference = enrolled[0]

    # Genuine attempts: remaining images of the enrolled person
    genuine_distances = [
        float(face_recognition.face_distance([reference], e)[0])
        for e in enrolled[1:]
    ]

    # Impostor attempts: all images of everyone else
    impostor_distances = []
    for person in people:
        if person == ENROLLED_PERSON:
            continue
        for e in all_encodings[person]:
            impostor_distances.append(
                float(face_recognition.face_distance([reference], e)[0])
            )

    print(f"\nGenuine attempts: {len(genuine_distances)}")
    print(f"Impostor attempts: {len(impostor_distances)}")

    g = np.array(genuine_distances)
    i = np.array(impostor_distances)

    print(f"\nGenuine distances:  min={g.min():.4f}  max={g.max():.4f}  mean={g.mean():.4f}")
    print(f"Impostor distances: min={i.min():.4f}  max={i.max():.4f}  mean={i.mean():.4f}")

    # ROC curve — negate distance so higher score = more likely genuine
    labels = np.concatenate([np.ones(len(g)), np.zeros(len(i))])
    scores = np.concatenate([-g, -i])
    fpr, tpr, thresholds = roc_curve(labels, scores)
    roc_auc = auc(fpr, tpr)

    # Threshold sweep
    print("\nThreshold sweep:")
    print(f"{'Thresh':>8} {'FAR':>10} {'FRR':>10} {'Accuracy':>10}")
    for t in [0.3, 0.4, 0.5, 0.6, 0.7]:
        far = float(np.mean(i <= t))
        frr = float(np.mean(g > t))
        acc = 1.0 - (far * len(i) + frr * len(g)) / (len(i) + len(g))
        print(f"{t:>8.2f} {far:>10.4f} {frr:>10.4f} {acc:>10.4f}")

    # Equal Error Rate
    eer_idx = np.argmin(np.abs((1 - tpr) - fpr))
    eer = (fpr[eer_idx] + (1 - tpr[eer_idx])) / 2
    print(f"\nEqual Error Rate (EER): {eer:.4f}")
    print(f"AUC: {roc_auc:.4f}")

    # Plots
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    axes[0].hist(g, bins=15, alpha=0.7, label="Genuine", color="green")
    axes[0].hist(i, bins=15, alpha=0.7, label="Impostor", color="red")
    axes[0].axvline(0.5, color="black", linestyle="--", label="Threshold (0.5)")
    axes[0].set_xlabel("Euclidean distance")
    axes[0].set_ylabel("Count")
    axes[0].set_title("Distance distributions")
    axes[0].legend()

    axes[1].plot(fpr, tpr, color="blue", lw=2, label=f"ROC (AUC = {roc_auc:.4f})")
    axes[1].plot([0, 1], [0, 1], color="grey", linestyle="--")
    axes[1].set_xlabel("False Acceptance Rate")
    axes[1].set_ylabel("True Acceptance Rate")
    axes[1].set_title("ROC curve")
    axes[1].legend()

    plt.tight_layout()
    plt.savefig("biometric_evaluation.png", dpi=150)
    print("\nPlot saved to biometric_evaluation.png")
    plt.show()


if __name__ == "__main__":
    main()