import math
import string
from collections import defaultdict


def estimate_entropy(password):
    if not password:
        return 0.0

    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += 32
    if any(c not in string.ascii_letters + string.digits + string.punctuation
           for c in password):
        pool += 33

    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def load_common_passwords(path):
    common = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                pw = line.strip()
                if pw:
                    common.add(pw)
    except FileNotFoundError:
        pass
    return common


def audit_vault(credentials, common_passwords=None, entropy_threshold=60.0):
    common_passwords = common_passwords or set()

    weak = []
    entropy_by_service = {}
    password_to_services = defaultdict(list)
    missing_totp = []

    for cred in credentials:
        service = cred.get("service", "?")
        pw = cred.get("password", "")

        e = estimate_entropy(pw)
        entropy_by_service[service] = e

        reasons = []
        if len(pw) < 12:
            reasons.append("short (<12 chars)")
        if e < entropy_threshold:
            reasons.append(f"low entropy ({e:.1f} bits)")
        if pw.lower() in common_passwords or pw in common_passwords:
            reasons.append("in common-password list")
        if reasons:
            weak.append((service, reasons))

        if pw:
            password_to_services[pw].append(service)

        if "totp_secret" not in cred:
            missing_totp.append(service)

    reused = {pw: svcs for pw, svcs in password_to_services.items() if len(svcs) > 1}

    return {
        "total": len(credentials),
        "weak": weak,
        "reused": reused,
        "missing_totp": missing_totp,
        "entropy": entropy_by_service,
    }


def print_report(report):
    print("=" * 60)
    print("  PASSWORD HEALTH AUDIT")
    print("=" * 60)
    print()
    print(f"Credentials audited: {report['total']}")
    print()

    weak = report["weak"]
    print(f"Weak passwords: {len(weak)}")
    if weak:
        for service, reasons in weak:
            print(f"  - {service}: {', '.join(reasons)}")
    else:
        print("  None.")
    print()

    reused = report["reused"]
    print(f"Reused password groups: {len(reused)}")
    if reused:
        for i, (pw, services) in enumerate(reused.items(), 1):
            masked = pw[:2] + "*" * max(0, len(pw) - 2)
            print(f"  Group {i}: {masked}  used by: {', '.join(services)}")
    else:
        print("  None.")
    print()

    missing = report["missing_totp"]
    print(f"Credentials without 2FA: {len(missing)} / {report['total']}")
    if missing:
        for service in missing:
            print(f"  - {service}")
    print()

    total = max(1, report["total"])
    weak_pct = 100 * len(weak) / total
    reuse_count = sum(len(svcs) for svcs in reused.values())
    reuse_pct = 100 * reuse_count / total
    twofa_pct = 100 * len(missing) / total

    score = 100 - weak_pct * 0.5 - reuse_pct * 0.3 - twofa_pct * 0.2
    score = max(0, min(100, score))

    print("=" * 60)
    print(f"  Overall health score: {score:.0f} / 100")
    print("=" * 60)
    if score >= 90:
        print("  Rating: EXCELLENT")
    elif score >= 75:
        print("  Rating: GOOD")
    elif score >= 50:
        print("  Rating: FAIR")
    else:
        print("  Rating: POOR")