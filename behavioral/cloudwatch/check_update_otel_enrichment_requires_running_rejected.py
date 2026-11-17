"""update-otel-enrichment-requires-running-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-otel-enrichment-requires-running-rejected"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


_NOT_RUNNING = ("ResourceNotFoundException", "OTel enrichment is not enabled for this account")


def expect_error(fn, code, message):
    """Call fn(); assert it raises exactly (code, message). An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        got = (error.get("Code"), error.get("Message"))
        assert got == (code, message), f"expected ({code!r}, {message!r}), got {got}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cloudwatch-otel-enrichment")
def run(ctx) -> None:
    """UpdateOTelEnrichment is rejected with ResourceNotFoundException while OTel enrichment
    is stopped for the account; once started, the identical update succeeds and is reflected
    in GetOTelEnrichment.
    """
    cw = ctx.client("cloudwatch")
    original_status = cw.get_otel_enrichment()["Status"]

    def _restore():
        # UpdateOTelEnrichment requires Running, so clear the filters this check sets
        # while enrichment is running, then put the on/off toggle back as found.
        current = cw.get_otel_enrichment()["Status"]
        if current != "Running":
            cw.start_otel_enrichment()
            _poll_until(
                lambda: cw.get_otel_enrichment()["Status"], lambda s: s == "Running",
                timeout_s=60, interval_s=3, description="StartOTelEnrichment before restore",
            )
        cw.update_otel_enrichment()
        if original_status == "Stopped":
            cw.stop_otel_enrichment()
            _poll_until(
                lambda: cw.get_otel_enrichment()["Status"], lambda s: s == "Stopped",
                timeout_s=60, interval_s=3, description="restoring the original Stopped status",
            )

    ctx.on_cleanup(_restore)

    if original_status == "Running":
        cw.stop_otel_enrichment()
        _poll_until(
            lambda: cw.get_otel_enrichment()["Status"], lambda s: s == "Stopped",
            timeout_s=60, interval_s=3, description="StopOTelEnrichment before the negative",
        )

    namespace = ctx.unique_name("sim2real-behav-cwprobe-otel-ns-")
    expect_error(
        lambda: cw.update_otel_enrichment(IncludeFilters=[{"Namespace": namespace}]),
        *_NOT_RUNNING,
    )

    still_stopped = cw.get_otel_enrichment()
    assert still_stopped["Status"] == "Stopped", (
        f"the rejected update must not have started enrichment, got {still_stopped['Status']!r}"
    )
    assert "IncludeFilters" not in still_stopped or still_stopped["IncludeFilters"] == [], (
        f"the rejected update must not have stored IncludeFilters, got {still_stopped.get('IncludeFilters')!r}"
    )

    cw.start_otel_enrichment()
    _poll_until(
        lambda: cw.get_otel_enrichment()["Status"], lambda s: s == "Running",
        timeout_s=60, interval_s=3, description="StartOTelEnrichment before the positive control",
    )

    updated = cw.update_otel_enrichment(IncludeFilters=[{"Namespace": namespace}])
    assert updated["IncludeFilters"] == [{"Namespace": namespace}], (
        f"the identical update while running: expected IncludeFilters=[{{'Namespace': {namespace!r}}}], "
        f"got {updated.get('IncludeFilters')!r}"
    )

    reflected = cw.get_otel_enrichment()
    assert reflected["IncludeFilters"] == [{"Namespace": namespace}], (
        f"GetOTelEnrichment: expected IncludeFilters=[{{'Namespace': {namespace!r}}}], "
        f"got {reflected.get('IncludeFilters')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
