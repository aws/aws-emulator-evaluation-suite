"""list-insights-metric-data-invalid-event-source-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-insights-metric-data-invalid-event-source-rejected"
GROUP = "telemetry"
SERVICES = ["cloudtrail"]


@tags("axis:rejection", "cap:c2", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListInsightsMetricData answers ValidationException with the eventSource pattern message for a malformed
    EventSource, and echoes EventSource/EventName with equal-length Timestamps and Values for a valid one."""
    ct = ctx.client("cloudtrail")

    code, message = _error(
        lambda: ct.list_insights_metric_data(
            EventSource="Not A Valid Source!!",
            EventName="ConsoleLogin",
            InsightType="ApiCallRateInsight",
        )
    )
    assert code == "ValidationException", code
    assert message == (
        "1 validation error detected: Value at 'eventSource' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: ^[a-z0-9_-]+\\.amazonaws\\.com$"
    ), message

    ok = ct.list_insights_metric_data(
        EventSource="iam.amazonaws.com",
        EventName="ConsoleLogin",
        InsightType="ApiCallRateInsight",
    )
    assert ok["EventSource"] == "iam.amazonaws.com", ok
    assert ok["EventName"] == "ConsoleLogin", ok
    assert len(ok["Timestamps"]) == len(ok["Values"]), ok


def _error(fn) -> tuple[str, str | None]:
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises,
    so a target accepting a call AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
