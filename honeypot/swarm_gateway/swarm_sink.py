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
  * Windows (Stage 1 rerun): every sample carries the time it was recorded.
    A small cell's pool is its real forwards from the last AGE_REAL seconds
    (newest WINDOW); if fewer than MIN_REAL, calibration samples from the last
    AGE_CAL seconds top it up to WINDOW; if still under MIN_POOL, the newest
    samples of any age are added (counted as "stale"). Large bodies keep the
    newest WINDOW points of any age (unchanged from Stage 1).
  * Cold start (Stage 1 rerun): a cold-excess sample is added only to the
    first diverted target after a boot, and only if no real forward has
    completed before it.

Nothing here knows about seats or containment: the target for a request
depends only on its class, its size and the exit's recent real forwards.
"""

import random
import secrets
import statistics
import threading
import time
from collections import deque

NO_BODY, URLENCODED, MULTIPART, OTHER = "no_body", "urlencoded", "multipart", "other"
CLASSES = (NO_BODY, URLENCODED, MULTIPART, OTHER)
# (upper bound in bytes, bucket name); bodies above the last bound are "large".
SMALL_BUCKETS = ((1024, "1k"), (4096, "4k"), (16384, "16k"), (65536, "64k"))
LARGE = "large"
LARGE_MIN = 65536
WINDOW = 200
AGE_REAL = 5.0     # s: real samples younger than this are "fresh"
AGE_CAL = 15.0     # s: calibration samples younger than this may top up a cell
MIN_REAL = 30      # fresh real samples at which calibration top-up stops
MIN_POOL = 10      # below this, the newest samples of any age are added


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
    def __init__(self, window: int = WINDOW, rng: random.Random | None = None, clock=None):
        self.window = window
        self.rng = rng or random.Random(secrets.randbits(64))
        self.clock = clock or time.monotonic
        self.lock = threading.Lock()
        self.real: dict = {}        # (cls, bucket) -> deque of (t, ms)
        self.cal: dict = {}
        self.real_large: dict = {}  # cls -> deque of (kb, ms)
        self.cal_large: dict = {}
        self.cold_excess: list[float] = []
        self.first_real_done = False
        self.cold_used = False      # the first diverted target after boot has been drawn
        self.counts = {"real": 0, "cal": 0, "targets": 0, "targets_cold": 0, "fallbacks": 0,
                       "pool_real_only": 0, "pool_topped_up": 0, "stale": 0}

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
                self._dq(self.real if real else self.cal, (cls, bucket)).append((self.clock(), ms))
            self.counts["real" if real else "cal"] += 1
            if real:
                self.first_real_done = True

    def set_cold_excess(self, samples) -> None:
        with self.lock:
            self.cold_excess = [float(s) for s in samples]

    # ------------------------------------------------------------ sampling

    def _pool(self, real, cal):
        """Large bodies: the newest real points topped up with calibration."""
        pool = list(real or ())
        if len(pool) < self.window and cal:
            need = self.window - len(pool)
            pool += list(cal)[-need:]
        return pool

    def _cell_pool(self, key, count: bool = True):
        """A small cell's pool (ms values), by the Stage 1 rerun rules."""
        now = self.clock()
        real = list(self.real.get(key) or ())
        cal = list(self.cal.get(key) or ())
        fresh = [ms for t, ms in real if now - t <= AGE_REAL][-self.window:]
        if len(fresh) >= MIN_REAL:
            if count:
                self.counts["pool_real_only"] += 1
            return fresh
        pool = fresh + [ms for t, ms in cal if now - t <= AGE_CAL][-(self.window - len(fresh)):]
        if count:
            self.counts["pool_topped_up"] += 1
        if len(pool) < MIN_POOL:
            # newest first within each source: real first, then calibration
            old_real = [ms for t, ms in reversed(real) if now - t > AGE_REAL]
            old_cal = [ms for t, ms in reversed(cal) if now - t > AGE_CAL]
            extra = (old_real + old_cal)[:MIN_POOL - len(pool)]
            if extra and count:
                self.counts["stale"] += 1
            pool += extra
        return pool

    def _small_pool(self, cls, bucket):
        pool = self._cell_pool((cls, bucket))
        if pool:
            return pool
        # Fallbacks (counted): the same class's nearest bucket, then any class.
        self.counts["fallbacks"] += 1
        order = ["0"] + [n for _, n in SMALL_BUCKETS]
        i = order.index(bucket) if bucket in order else len(order) - 1
        for name in sorted(order, key=lambda n: abs(order.index(n) - i)):
            pool = self._cell_pool((cls, name), count=False)
            if pool:
                return pool
        for key in list(self.real) + list(self.cal):
            pool = self._cell_pool(key, count=False)
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
            if not self.cold_used:
                self.cold_used = True
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
            now = self.clock()

            def cell(v, age):
                v = list(v)
                return {**s(ms for _, ms in v), "fresh": sum(1 for t, _ in v if now - t <= age)}
            return {
                "window": self.window,
                "rules": {"age_real_s": AGE_REAL, "age_cal_s": AGE_CAL, "min_real": MIN_REAL,
                          "min_pool": MIN_POOL},
                "first_real_done": self.first_real_done,
                "cold_used": self.cold_used,
                "counts": dict(self.counts),
                "real": {f"{c}/{b}": cell(v, AGE_REAL) for (c, b), v in sorted(self.real.items())},
                "cal": {f"{c}/{b}": cell(v, AGE_CAL) for (c, b), v in sorted(self.cal.items())},
                "real_large": {c: s(ms for _, ms in v) for c, v in sorted(self.real_large.items())},
                "cal_large": {c: s(ms for _, ms in v) for c, v in sorted(self.cal_large.items())},
                "cold_excess": s(self.cold_excess),
            }
