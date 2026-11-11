"""otel-enrichment-start-stop-status-lifecycle."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "otel-enrichment-start-stop-status-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:cloudwatch-otel-enrichment",
)
def run(ctx) -> None:
    """StartOTelEnrichment flips account-wide status to Running (via
    GetOTelEnrichment); StopOTelEnrichment reverts it to Stopped."""
    cw = ctx.client("cloudwatch")

    baseline_status = cw.get_otel_enrichment()["Status"]
    assert baseline_status in ("Running", "Stopped"), (
        f"expected GetOTelEnrichment to report Running or Stopped, got {baseline_status!r}"
    )

    def _restore() -> None:
        if baseline_status == "Running":
            cw.start_otel_enrichment()
        else:
            cw.stop_otel_enrichment()

    ctx.on_cleanup(_restore)

    # 1. Start -> Running.
    cw.start_otel_enrichment()
    status = _poll_until(
        lambda: cw.get_otel_enrichment()["Status"],
        lambda s: s == "Running",
        timeout_s=30,
        interval_s=2,
    )
    assert status == "Running", f"expected Running after StartOTelEnrichment, got {status!r}"

    # 2. Stop -> Stopped.
    cw.stop_otel_enrichment()
    status = _poll_until(
        lambda: cw.get_otel_enrichment()["Status"],
        lambda s: s == "Stopped",
        timeout_s=30,
        interval_s=2,
    )
    assert status == "Stopped", f"expected Stopped after StopOTelEnrichment, got {status!r}"


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 30.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
