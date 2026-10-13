import time
import statistics
from crypto_utils import generate_salt, derive_key


def benchmark_pbkdf2(runs=10):
    times = []
    for i in range(runs):
        salt = generate_salt()
        start = time.perf_counter()
        derive_key("benchmark_password", salt)
        elapsed = time.perf_counter() - start
        times.append(elapsed)
        print(f"Run {i+1}/{runs}: {elapsed:.3f}s")

    avg = statistics.mean(times)
    median = statistics.median(times)
    min_t = min(times)
    max_t = max(times)

    print("\n--- PBKDF2 Benchmark Results ---")
    print(f"Runs: {runs}")
    print(f"Average: {avg:.3f}s")
    print(f"Median:  {median:.3f}s")
    print(f"Min:     {min_t:.3f}s")
    print(f"Max:     {max_t:.3f}s")
    print(f"\nSuccess criterion (median >= 0.5s): "
          f"{'PASS' if median >= 0.5 else 'FAIL'}")


if __name__ == "__main__":
    benchmark_pbkdf2(runs=10)