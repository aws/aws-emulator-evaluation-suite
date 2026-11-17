"""update-otel-enrichment-rejected-before-start."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-otel-enrichment-rejected-before-start"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]

_NAMESPACE = "Sim2RealProbe/CloudWatchRMC-StartBeforeUpdate"
_NOT_ENABLED = ("ResourceNotFoundException", "OTel enrichment is not enabled for this account")


def _retrying(fn, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            throttled = exc.response.get("Error", {}).get("Code") == "ThrottlingException"
            if not throttled or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, f"expected code {code!r}, got {err['Code']!r}"
        assert err["Message"] == message, f"expected message {message!r}, got {err['Message']!r}"
        return
    raise AssertionError(f"expected ({code}, {message!r}) but the call succeeded: {result!r}")


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "plane:control",
    "resource:account-singleton:cloudwatch-otel-enrichment",
)
def run(ctx) -> None:
    """UpdateOTelEnrichment is rejected with ResourceNotFoundException while enrichment is Stopped,
    and the identical call succeeds once StartOTelEnrichment has turned enrichment on."""
    cw = ctx.client("cloudwatch")

    original = _retrying(lambda: cw.get_otel_enrichment())

    def _restore() -> None:
        if original["Status"] == "Running":
            _retrying(
                lambda: cw.start_otel_enrichment(
                    IncludeFilters=original.get("IncludeFilters", []),
                    ExcludeFilters=original.get("ExcludeFilters", []),
                )
            )
        else:
            _retrying(lambda: cw.stop_otel_enrichment())

    ctx.on_cleanup(_restore)

    if original["Status"] == "Running":
        _retrying(lambda: cw.stop_otel_enrichment())
        stopped = _retrying(lambda: cw.get_otel_enrichment())
        assert stopped["Status"] == "Stopped", (
            f"StopOTelEnrichment left Status as {stopped['Status']!r}, expected Stopped"
        )

    expect_error(
        lambda: cw.update_otel_enrichment(IncludeFilters=[{"Namespace": _NAMESPACE}]),
        *_NOT_ENABLED,
    )

    _retrying(lambda: cw.start_otel_enrichment())
    running = _retrying(lambda: cw.get_otel_enrichment())
    assert running["Status"] == "Running", (
        f"StartOTelEnrichment left Status as {running['Status']!r}, expected Running"
    )

    updated = _retrying(
        lambda: cw.update_otel_enrichment(IncludeFilters=[{"Namespace": _NAMESPACE}])
    )
    assert updated["IncludeFilters"] == [{"Namespace": _NAMESPACE}], (
        "the identical UpdateOTelEnrichment call, retried after StartOTelEnrichment, returned "
        f"IncludeFilters {updated['IncludeFilters']!r}, expected only {_NAMESPACE!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
