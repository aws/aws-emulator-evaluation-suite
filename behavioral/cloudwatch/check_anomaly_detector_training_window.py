"""anomaly-detector-training-window."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "anomaly-detector-training-window"
GROUP = 'anomaly-detector'
SERVICES = ['cloudwatch']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _assert_untrained_throughout(probe, *, duration_s, interval_s):
    """Read repeatedly across duration_s (a bounded, ticked wait, never a bare
    sleep): every read in the window must still be untrained, so a detector that
    flips to TRAINED partway through is caught at the tick it happens, not just
    at the end.
    """
    deadline = time.monotonic() + duration_s
    ticks = 0
    while time.monotonic() < deadline:
        time.sleep(interval_s)
        elapsed = duration_s - (deadline - time.monotonic())
        d = probe()
        assert d is not None, "anomaly detector disappeared during its training window"
        ticks += 1
        assert d["StateValue"] in ("PENDING_TRAINING", "TRAINED_INSUFFICIENT_DATA"), (
            f"expected the detector to remain untrained after {elapsed:.1f}s of wall-clock time "
            f"(the training window requires far more real history than that), got {d['StateValue']}"
        )
    assert ticks > 0, "training window check made no observations"


def _delete_if_present(cw, spec):
    """Teardown: delete the detector unless the check already did."""
    from botocore.exceptions import ClientError

    try:
        cw.delete_anomaly_detector(**spec)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new anomaly detector reads PENDING_TRAINING or TRAINED_INSUFFICIENT_DATA, never TRAINED,
    at every read over 15 s, and DeleteAnomalyDetector removes it."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    metric_name = "Latency"
    spec = dict(Namespace=namespace, MetricName=metric_name, Stat="Average")

    ctx.on_cleanup(lambda _s=spec: _delete_if_present(cw, _s))
    cw.put_anomaly_detector(**spec)

    def probe():
        resp = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)
        dets = resp.get("AnomalyDetectors", [])
        return dets[0] if dets else None

    det = _poll_until(probe, lambda d: d is not None, timeout_s=30, interval_s=2, description="detector visible")
    assert det["StateValue"] in ("PENDING_TRAINING", "TRAINED_INSUFFICIENT_DATA"), (
        f"expected a freshly created detector to still be within its training window "
        f"(not yet TRAINED), got {det['StateValue']}"
    )

    # The training window needs far more history than a few seconds provide, so the detector
    # must stay untrained; the wait is a ticked poll that asserts untrained at every tick.
    _assert_untrained_throughout(probe, duration_s=15, interval_s=3)
    det2 = probe()
    assert det2["StateValue"] in ("PENDING_TRAINING", "TRAINED_INSUFFICIENT_DATA"), (
        f"expected the detector to remain untrained after only 15s of wall-clock time "
        f"(the training window requires far more real history than that), got {det2['StateValue']}"
    )

    cw.delete_anomaly_detector(**spec)
    resp = cw.describe_anomaly_detectors(Namespace=namespace, MetricName=metric_name)
    assert resp.get("AnomalyDetectors", []) == [], "anomaly detector should be gone after delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
