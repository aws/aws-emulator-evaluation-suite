"""get-recommendations-start-after-end-rejected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-recommendations-start-after-end-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeguruprofiler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRecommendations with startTime after endTime fails with ValidationException and its exact message,
    while a well-ordered range on the same group returns empty anomalies and recommendations.
    """
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))
    cgp.create_profiling_group(
        profilingGroupName=name, agentOrchestrationConfig={"profilingEnabled": True}
    )

    # one fixed millisecond value with no trailing zero, so every run sends and renders the
    # same fraction as AWS's message does
    now = datetime.now(timezone.utc).replace(microsecond=123000)
    start = now
    end = now - timedelta(hours=1)

    code, message = _error_code(
        lambda: cgp.get_recommendations(
            profilingGroupName=name, startTime=start, endTime=end
        )
    )
    assert code == "ValidationException", (code, message)
    expected_message = (
        f"Interval start time ({_iso_ms(start)}) must be before end time ({_iso_ms(end)})"
    )
    assert message == expected_message, (message, expected_message)

    # positive control: a validly-ordered range on the same operation must not also come
    # back as ValidationException, so the rejection above is specific to start > end.
    ok = cgp.get_recommendations(profilingGroupName=name, startTime=end, endTime=start)
    assert ok["profilingGroupName"] == name, ok
    assert ok.get("anomalies", []) == [], ok.get("anomalies")
    assert ok.get("recommendations", []) == [], ok.get("recommendations")


def _iso_ms(dt):
    return f"{dt:%Y-%m-%dT%H:%M:%S}.{dt.microsecond // 1000:03d}Z"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
