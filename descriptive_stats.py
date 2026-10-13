# descriptive_stats.py
"""
Descriptive statistics for both project datasets:
  1. RockYou password sample
  2. Face image dataset + biometric distance distributions
"""

import os
import string
import numpy as np
import face_recognition
from collections import Counter


ROCKYOU_FILE = "rockyou_sample.txt"
DATASET_DIR = "dataset"
ENROLLED_PERSON = "admin"


def describe_rockyou():
    print("=" * 68)
    print("  DATASET 1: ROCKYOU PASSWORD SAMPLE")
    print("=" * 68)

    with open(ROCKYOU_FILE, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [l.strip() for l in f if l.strip()]

    raw_n = len(passwords)
    passwords = list(dict.fromkeys(passwords))

    lengths = np.array([len(p) for p in passwords])
    n = len(passwords)

    print(f"\nSample size (n):        {n}")
    print(f"Duplicates removed:     {raw_n - n}")

    print(f"\nPassword length:")
    print(f"  mean      {lengths.mean():.2f}")
    print(f"  median    {np.median(lengths):.0f}")
    print(f"  std dev   {lengths.std():.2f}")
    print(f"  min       {lengths.min()}")
    print(f"  max       {lengths.max()}")
    print(f"  Q1        {np.percentile(lengths, 25):.0f}")
    print(f"  Q3        {np.percentile(lengths, 75):.0f}")

    def pct(pred):
        c = sum(1 for p in passwords if pred(p))
        return c, 100 * c / n

    print(f"\nCharacter class frequency:")
    for label, pred in [
        ("lowercase", lambda p: any(c.islower() for c in p)),
        ("uppercase", lambda p: any(c.isupper() for c in p)),
        ("digits",    lambda p: any(c.isdigit() for c in p)),
        ("symbols",   lambda p: any(c in string.punctuation for c in p)),
        ("digits only", lambda p: p.isdigit()),
        ("letters only", lambda p: p.isalpha()),
    ]:
        c, p = pct(pred)
        print(f"  {label:14s} {c:3d}  ({p:5.1f}%)")

    short = sum(1 for l in lengths if l < 8)
    print(f"\nLength thresholds:")
    print(f"  < 8 chars     {short:3d}  ({100*short/n:5.1f}%)")
    print(f"  < 12 chars    {sum(1 for l in lengths if l < 12):3d}  "
          f"({100*sum(1 for l in lengths if l < 12)/n:5.1f}%)")

    print(f"\nMost common passwords:")
    for pw, count in Counter(passwords).most_common(5):
        print(f"  {pw!r:20s} x{count}")


def describe_faces():
    print("\n" + "=" * 68)
    print("  DATASET 2: FACE IMAGE DATASET")
    print("=" * 68)

    if not os.path.isdir(DATASET_DIR):
        print("\nDataset directory not found. Skipping.")
        return None

    people = sorted(p for p in os.listdir(DATASET_DIR)
                    if os.path.isdir(os.path.join(DATASET_DIR, p)))

    counts = {}
    for person in people:
        folder = os.path.join(DATASET_DIR, person)
        imgs = [f for f in os.listdir(folder)
                if f.lower().endswith((".jpg", ".png"))]
        counts[person] = len(imgs)

    values = list(counts.values())
    print(f"\nClasses (participants):  {len(counts)}")
    print(f"Total images:            {sum(values)}")

    print(f"\nImages per participant:")
    for person, count in counts.items():
        print(f"  {person:12s}  {count}")

    print(f"\nClass balance:")
    print(f"  min / max        {min(values)} / {max(values)}")
    print(f"  balance ratio    {min(values)/max(values):.2f}")

    return counts


def describe_biometric_distances():
    print("\n" + "=" * 68)
    print("  BIOMETRIC DISTANCE DISTRIBUTIONS")
    print("=" * 68)

    if not os.path.isdir(DATASET_DIR):
        return

    def load(person):
        folder = os.path.join(DATASET_DIR, person)
        out = []
        for f in sorted(os.listdir(folder)):
            if not f.lower().endswith((".jpg", ".png")):
                continue
            img = face_recognition.load_image_file(os.path.join(folder, f))
            locs = face_recognition.face_locations(img)
            if len(locs) == 1:
                enc = face_recognition.face_encodings(img, locs)
                if enc:
                    out.append(enc[0])
        return np.array(out)

    people = sorted(p for p in os.listdir(DATASET_DIR)
                    if os.path.isdir(os.path.join(DATASET_DIR, p)))
    encodings = {p: load(p) for p in people}

    if ENROLLED_PERSON not in encodings or len(encodings[ENROLLED_PERSON]) < 2:
        print(f"\nEnrolled person '{ENROLLED_PERSON}' has insufficient data.")
        return

    ref = encodings[ENROLLED_PERSON][0]

    genuine = [float(face_recognition.face_distance([ref], e)[0])
               for e in encodings[ENROLLED_PERSON][1:]]

    impostor = []
    for p in people:
        if p == ENROLLED_PERSON:
            continue
        for e in encodings[p]:
            impostor.append(float(face_recognition.face_distance([ref], e)[0]))

    g, i = np.array(genuine), np.array(impostor)

    def stats(name, arr):
        print(f"\n{name} (n={len(arr)}):")
        print(f"  mean     {arr.mean():.4f}")
        print(f"  median   {np.median(arr):.4f}")
        print(f"  std      {arr.std():.4f}")
        print(f"  min      {arr.min():.4f}")
        print(f"  max      {arr.max():.4f}")
        print(f"  Q1       {np.percentile(arr, 25):.4f}")
        print(f"  Q3       {np.percentile(arr, 75):.4f}")

    stats("Genuine distances", g)
    stats("Impostor distances", i)

    gap = i.min() - g.max()
    print(f"\nSeparation:")
    print(f"  max genuine    {g.max():.4f}")
    print(f"  min impostor   {i.min():.4f}")
    print(f"  gap            {gap:.4f}")
    print(f"  overlap        {'YES' if gap <= 0 else 'NO'}")


if __name__ == "__main__":
    describe_rockyou()
    describe_faces()
    describe_biometric_distances()
    print()