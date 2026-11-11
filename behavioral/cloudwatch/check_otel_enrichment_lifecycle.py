"""otel-enrichment-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "otel-enrichment-lifecycle"
GROUP = 'data-plane'
SERVICES = ['cloudwatch']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-otel-enrichment")
def run(ctx) -> None:
    """StartOTelEnrichment activates enrichment reflected in GetOTelEnrichment status; StopOTelEnrichment deactivates it."""
    cw = ctx.client("cloudwatch")

    def _is_throttle(exc: ClientError) -> bool:
        return exc.response.get("Error", {}).get("Code") in ("Throttling", "ThrottlingException")

    def _get_status():
        try:
            return cw.get_otel_enrichment()["Status"]
        except ClientError as exc:
            if _is_throttle(exc):
                return None
            raise

    def _call_retrying(fn):
        def probe():
            try:
                fn()
                return True
            except ClientError as exc:
                if _is_throttle(exc):
                    return False
                raise

        return _poll_until(
            probe, lambda ok: ok is True, timeout_s=60, interval_s=5, description="call succeeds past throttling"
        )

    original = _poll_until(
        _get_status, lambda s: s is not None, timeout_s=60, interval_s=5, description="GetOTelEnrichment succeeds"
    )
    # The account's enrichment switch is restored to the state read above; a failed restore raises.
    def _restore() -> None:
        if original == "Running":
            _call_retrying(lambda: cw.start_otel_enrichment())
        else:
            _call_retrying(lambda: cw.stop_otel_enrichment())

    ctx.on_cleanup(_restore)

    _call_retrying(lambda: cw.start_otel_enrichment())
    state = _poll_until(_get_status, lambda s: s == "Running", timeout_s=60, interval_s=5)
    assert state == "Running", f"expected Running after StartOTelEnrichment, got {state}"

    _call_retrying(lambda: cw.stop_otel_enrichment())
    state2 = _poll_until(_get_status, lambda s: s == "Stopped", timeout_s=60, interval_s=5)
    assert state2 == "Stopped", f"expected Stopped after StopOTelEnrichment, got {state2}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
