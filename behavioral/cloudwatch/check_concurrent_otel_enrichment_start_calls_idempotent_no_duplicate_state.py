"""concurrent-otel-enrichment-start-calls-idempotent-no-duplicate-state."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-otel-enrichment-start-calls-idempotent-no-duplicate-state"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-otel-enrichment")
def run(ctx) -> None:
    """Concurrent StartOTelEnrichment calls all succeed, GetOTelEnrichment reads Running on two
    reads, and a single StopOTelEnrichment makes it read Stopped: the starts share one
    account-level setting."""
    cw = ctx.client("cloudwatch")
    ctx.on_cleanup(lambda: cw.stop_otel_enrichment())

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(cw.start_otel_enrichment) for _ in range(8)]
        results = [f.result() for f in futures]  # raises if any concurrent call errored
    assert all(isinstance(r, dict) for r in results), (
        f"expected 8 dict responses from the 8 concurrent StartOTelEnrichment calls, got {results!r}"
    )

    status = cw.get_otel_enrichment()["Status"]
    assert status == "Running", f"expected enrichment status Running after concurrent starts, got {status}"

    status_again = cw.get_otel_enrichment()["Status"]
    assert status_again == "Running", f"enrichment status was not stable across repeated reads: {status} then {status_again}"

    cw.stop_otel_enrichment()
    status_after_single_stop = _poll_until_stopped(cw)
    assert status_after_single_stop == "Stopped", (
        f"a single StopOTelEnrichment call after 8 concurrent Start calls left status "
        f"{status_after_single_stop!r} instead of Stopped -- indicates duplicate/independent "
        f"enrichment state was created by the concurrent starts"
    )


def _poll_until_stopped(cw, timeout_s: float = 30.0, interval_s: float = 1.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cw.get_otel_enrichment()["Status"]
        if last == "Stopped":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"OTelEnrichmentStatus never reached 'Stopped' after a single Stop call, last was {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
