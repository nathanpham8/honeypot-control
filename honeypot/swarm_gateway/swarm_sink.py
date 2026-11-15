"""Timing model for the swarm exit's sink (step 3, Stage 1). Pure Python.

A diverted request must be answered after the delay a real delivery would
have taken. The delay is drawn from measured real forward latencies, where
"latency" is the exit's span from WSGI entry to reply-ready, the same span for
both paths. Design: docs/swarm-pilot/step3-plan.md, "Stage 0 gate: changes for
Stage 1", section 4.

  * Request type classes: no body; urlencoded (explicit, or a body with no
    content type, which the forward turns into urlencoded); multipart; other.
  * Size: buckets up to 64 KB; above 64 KB a per-class straight-line fit
    latency = a + b * KB with resampled residuals.
  * Windows: per (class, bucket) cell the 200 most recent successful real
    forwards, topped up with the most recent calibration samples while a cell
    has fewer than 200 real ones.
  * Cold start: until the first real forward after a boot completes, a cold
    excess sample (from fresh calibration collectors) is added to each target.

Nothing here knows about seats or containment: the target for a request
depends only on its class, its size and the exit's recent real forwards.
"""

import random
import secrets
import statistics
import threading
from collections import deque

NO_BODY, URLENCODED, MULTIPART, OTHER = "no_body", "urlencoded", "multipart", "other"
CLASSES = (NO_BODY, URLENCODED, MULTIPART, OTHER)
# (upper bound in bytes, bucket name); bodies above the last bound are "large".
SMALL_BUCKETS = ((1024, "1k"), (4096, "4k"), (16384, "16k"), (65536, "64k"))
LARGE = "large"
LARGE_MIN = 65536
WINDOW = 200


def classify(content_type: str | None, body_len: int) -> tuple[str, str]:
    """(class, bucket) for a request with this content type and body length."""
    if not body_len:
        return NO_BODY, "0"
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if ct in ("", "application/x-www-form-urlencoded"):
        cls = URLENCODED
    elif ct == "multipart/form-data":
        cls = MULTIPART
    else:
        cls = OTHER
    for bound, name in SMALL_BUCKETS:
        if body_len <= bound:
            return cls, name
    return cls, LARGE


def cells() -> list[tuple[str, str]]:
    """Every small cell the calibration must cover."""
    out = [(NO_BODY, "0")]
    for cls in (URLENCODED, MULTIPART, OTHER):
        out += [(cls, name) for _, name in SMALL_BUCKETS]
    return out


def bucket_range(bucket: str) -> tuple[int, int]:
    """(lowest, highest) body size in a small bucket."""
    lo = 1
    for bound, name in SMALL_BUCKETS:
        if name == bucket:
            return lo, bound
        lo = bound + 1
    raise ValueError(bucket)


def fit_line(points):
    """Least squares y = a + b x over [(x, y)]; returns (a, b, residuals)."""
    n = len(points)
    mx = sum(x for x, _ in points) / n
    my = sum(y for _, y in points) / n
    var = sum((x - mx) ** 2 for x, _ in points)
    b = 0.0 if var == 0 else sum((x - mx) * (y - my) for x, y in points) / var
    a = my - b * mx
    return a, b, [y - (a + b * x) for x, y in points]


class SinkModel:
    def __init__(self, window: int = WINDOW, rng: random.Random | None = None):
        self.window = window
        self.rng = rng or random.Random(secrets.randbits(64))
        self.lock = threading.Lock()
        self.real: dict = {}        # (cls, bucket) -> deque of ms
        self.cal: dict = {}
        self.real_large: dict = {}  # cls -> deque of (kb, ms)
        self.cal_large: dict = {}
        self.cold_excess: list[float] = []
        self.first_real_done = False
        self.counts = {"real": 0, "cal": 0, "targets": 0, "targets_cold": 0, "fallbacks": 0}

    def _dq(self, table, key):
        if key not in table:
            table[key] = deque(maxlen=self.window)
        return table[key]

    # ------------------------------------------------------------ recording

    def record(self, cls: str, bucket: str, size: int, ms: float, *, real: bool) -> None:
        with self.lock:
            if bucket == LARGE:
                self._dq(self.real_large if real else self.cal_large, cls).append((size / 1024, ms))
            else:
                self._dq(self.real if real else self.cal, (cls, bucket)).append(ms)
            self.counts["real" if real else "cal"] += 1
            if real:
                self.first_real_done = True

    def set_cold_excess(self, samples) -> None:
        with self.lock:
            self.cold_excess = [float(s) for s in samples]

    # ------------------------------------------------------------ sampling

    def _pool(self, real, cal):
        pool = list(real or ())
        if len(pool) < self.window and cal:
            need = self.window - len(pool)
            pool += list(cal)[-need:]
        return pool

    def _small_pool(self, cls, bucket):
        pool = self._pool(self.real.get((cls, bucket)), self.cal.get((cls, bucket)))
        if pool:
            return pool
        # Fallbacks (counted): the same class's nearest bucket, then any class.
        self.counts["fallbacks"] += 1
        order = ["0"] + [n for _, n in SMALL_BUCKETS]
        i = order.index(bucket) if bucket in order else len(order) - 1
        for name in sorted(order, key=lambda n: abs(order.index(n) - i)):
            pool = self._pool(self.real.get((cls, name)), self.cal.get((cls, name)))
            if pool:
                return pool
        for key in list(self.real) + list(self.cal):
            pool = self._pool(self.real.get(key), self.cal.get(key))
            if pool:
                return pool
        return []

    def _large_target(self, cls, size):
        pts = self._pool(self.real_large.get(cls), self.cal_large.get(cls))
        if len(pts) < 3:
            self.counts["fallbacks"] += 1
            for other in CLASSES:
                pts = self._pool(self.real_large.get(other), self.cal_large.get(other))
                if len(pts) >= 3:
                    break
        if len(pts) < 3:
            base = self._small_pool(cls, "64k")
            return (self.rng.choice(base) if base else 0.0) + 0.009 * (size - LARGE_MIN) / 1024
        a, b, resid = fit_line(pts)
        return a + b * size / 1024 + self.rng.choice(resid)

    def target_ms(self, cls: str, bucket: str, size: int) -> float:
        """Target latency (ms) for one diverted request."""
        with self.lock:
            if bucket == LARGE:
                t = self._large_target(cls, size)
            else:
                pool = self._small_pool(cls, bucket)
                t = self.rng.choice(pool) if pool else 0.0
            self.counts["targets"] += 1
            if not self.first_real_done and self.cold_excess:
                t += self.rng.choice(self.cold_excess)
                self.counts["targets_cold"] += 1
            return max(t, 0.0)

    # ------------------------------------------------------------ reporting

    def view(self) -> dict:
        with self.lock:
            def s(xs):
                xs = list(xs)
                return {"n": len(xs), "median": round(statistics.median(xs), 3) if xs else None}
            return {
                "window": self.window,
                "first_real_done": self.first_real_done,
                "counts": dict(self.counts),
                "real": {f"{c}/{b}": s(v) for (c, b), v in sorted(self.real.items())},
                "cal": {f"{c}/{b}": s(v) for (c, b), v in sorted(self.cal.items())},
                "real_large": {c: s(ms for _, ms in v) for c, v in sorted(self.real_large.items())},
                "cal_large": {c: s(ms for _, ms in v) for c, v in sorted(self.cal_large.items())},
                "cold_excess": s(self.cold_excess),
            }
