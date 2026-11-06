import time
from contextlib import contextmanager


@contextmanager
def measure(name):
    start = time.perf_counter()

    try:
        yield
    finally:
        elapsed = time.perf_counter() - start
        print(f"[TIMING] {name}: {elapsed:.2f}s")
