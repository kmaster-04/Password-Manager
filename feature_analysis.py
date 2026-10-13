# feature_analysis.py
"""
Feature inventory and importance ranking for both datasets.

Dataset 1 (RockYou): which password features best predict weakness?
Dataset 2 (Face): which encoding dimensions are most stable/discriminative?
"""

import os
import math
import string
import numpy as np
import face_recognition
from collections import Counter
from scipy.stats import pointbiserialr, spearmanr


ROCKYOU_FILE = "rockyou_sample.txt"
DATASET_DIR = "dataset"
ENROLLED_PERSON = "admin"


# ==================================================================
#  DATASET 1 — PASSWORDS
# ==================================================================

def raw_features(password):
    """Raw features: taken directly from the string, no transformation."""
    return {
        "length": len(password),
        "chars": password,
    }


def derived_features(password):
    """Derived features: computed from the raw string."""
    lower = sum(1 for c in password if c.islower())
    upper = sum(1 for c in password if c.isupper())
    digits = sum(1 for c in password if c.isdigit())
    symbols = sum(1 for c in password if c in string.punctuation)

    pool = 0
    if lower: pool += 26
    if upper: pool += 26
    if digits: pool += 10
    if symbols: pool += 32
    entropy = len(password) * math.log2(pool) if pool else 0.0

    return {
        "lower_count": lower,
        "upper_count": upper,
        "digit_count": digits,
        "symbol_count": symbols,
        "has_upper": int(upper > 0),
        "has_digit": int(digits > 0),
        "has_symbol": int(symbols > 0),
        "class_count": sum([lower > 0, upper > 0, digits > 0, symbols > 0]),
        "entropy_bits": round(entropy, 2),
        "is_numeric_only": int(password.isdigit()),
        "is_alpha_only": int(password.isalpha()),
        "unique_char_ratio": len(set(password)) / len(password),
        "repeat_ratio": 1 - (len(set(password)) / len(password)),
        "starts_with_digit": int(password[0].isdigit()),
    }


def password_importance():
    print("=" * 74)
    print("  DATASET 1: PASSWORD FEATURE IMPORTANCE")
    print("=" * 74)

    with open(ROCKYOU_FILE, "r", encoding="utf-8", errors="ignore") as f:
        passwords = list(dict.fromkeys(l.strip() for l in f if l.strip()))

    rows = []
    for pw in passwords:
        f = derived_features(pw)
        f["_password"] = pw
        rows.append(f)

    # Target: is this password "weak"? (below 40 bits entropy)
    y = np.array([1 if r["entropy_bits"] < 40 else 0 for r in rows])
    print(f"\nSamples: {len(rows)}")
    print(f"Weak (entropy < 40 bits): {y.sum()} ({100*y.mean():.1f}%)")

    # Feature-target correlation
    feature_names = [k for k in rows[0] if not k.startswith("_")]
    print(f"\nPoint-biserial correlation with 'weak' label:")
    print(f"{'Feature':<22} {'r':>10} {'|r|':>10}  Rank")
    print("-" * 56)

    results = []
    for name in feature_names:
        x = np.array([r[name] for r in rows], dtype=float)
        if x.std() == 0:
            continue
        try:
            r, _ = pointbiserialr(y, x)
        except Exception:
            continue
        results.append((name, r, abs(r)))

    results.sort(key=lambda t: t[2], reverse=True)
    for rank, (name, r, ar) in enumerate(results, 1):
        print(f"{name:<22} {r:>10.4f} {ar:>10.4f}  {rank}")

    # Most common passwords as a sanity check
    print(f"\nTop 5 passwords (most frequent in corpus):")
    for pw, c in Counter(passwords).most_common(5):
        f = derived_features(pw)
        print(f"  {pw!r:18s} len={f['length']:2d} entropy={f['entropy_bits']:5.1f} "
              f"classes={f['class_count']}")

    return results


# ==================================================================
#  DATASET 2 — FACE ENCODINGS
# ==================================================================

def load_encodings(person):
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


def face_importance():
    print("\n" + "=" * 74)
    print("  DATASET 2: FACE ENCODING DIMENSION IMPORTANCE")
    print("=" * 74)

    if not os.path.isdir(DATASET_DIR):
        print("Dataset not found.")
        return None

    people = sorted(p for p in os.listdir(DATASET_DIR)
                    if os.path.isdir(os.path.join(DATASET_DIR, p)))
    encodings = {p: load_encodings(p) for p in people}

    # --- Importance metric 1: within-person stability ---
    # A dimension is "stable" if it varies little across images of the
    # same person. Stable dimensions are good candidates for the fuzzy
    # extractor's sign-bit extraction.
    print("\nImportance metric 1: WITHIN-PERSON STABILITY")
    print("(low std across same-person images = stable = useful)\n")

    stability = {}
    for person, enc in encodings.items():
        if len(enc) < 2:
            continue
        stability[person] = np.std(enc, axis=0)

    if not stability:
        print("Insufficient data.")
        return None

    mean_stability = np.mean(list(stability.values()), axis=0)
    most_stable = np.argsort(mean_stability)[:15]
    least_stable = np.argsort(mean_stability)[-5:]

    print(f"  {'Dimension':>10}  {'Mean std':>10}")
    print("  " + "-" * 24)
    for i, d in enumerate(most_stable, 1):
        print(f"  {d:>10}  {mean_stability[d]:>10.4f}   rank {i}")

    print(f"\n  Least stable (avoid for fuzzy extractor):")
    for d in least_stable:
        print(f"  {d:>10}  {mean_stability[d]:>10.4f}")

    # --- Importance metric 2: between-person discriminability ---
    # A dimension is "discriminative" if different people have very
    # different mean values on it.
    print("\n\nImportance metric 2: BETWEEN-PERSON DISCRIMINABILITY")
    print("(large spread across people = discriminative)\n")

    person_means = np.array([np.mean(enc, axis=0) for enc in encodings.values()])
    between_std = np.std(person_means, axis=0)

    # Ratio of between-person to within-person variance
    discriminability = between_std / (mean_stability + 1e-9)
    top_disc = np.argsort(discriminability)[-15:][::-1]

    print(f"  {'Dimension':>10}  {'Between/within':>16}")
    print("  " + "-" * 30)
    for i, d in enumerate(top_disc, 1):
        print(f"  {d:>10}  {discriminability[d]:>16.4f}   rank {i}")

    print(f"\n  Cross-reference: top 10 dimensions in BOTH rankings")
    stable_set = set(most_stable.tolist())
    disc_set = set(top_disc.tolist())
    both = stable_set & disc_set
    if both:
        for d in sorted(both):
            print(f"    dimension {d:>4}  "
                  f"stability={mean_stability[d]:.4f}  "
                  f"discriminability={discriminability[d]:.4f}")
    else:
        print("    None — stability and discriminability trade off.")

    return {"stable": most_stable.tolist(),
            "discriminative": top_disc.tolist(),
            "stability_scores": mean_stability.tolist(),
            "discriminability_scores": discriminability.tolist()}


if __name__ == "__main__":
    password_importance()
    face_importance()
    print()