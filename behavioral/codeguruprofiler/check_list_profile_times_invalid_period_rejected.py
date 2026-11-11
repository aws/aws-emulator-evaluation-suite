"""list-profile-times-invalid-period-rejected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-profile-times-invalid-period-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeguruprofiler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListProfileTimes rejects a period value that is not one of the three supported ISO
    8601 durations (PT5M, PT1H, P1D) with ValidationException, while the same call using a
    valid period (positive control) succeeds even though there is no profile data yet."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"sim2real": "true"},
    )

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=1)

    code, message = _error_code(
        lambda: cgp.list_profile_times(
            profilingGroupName=name, startTime=start, endTime=end, period="P2D"
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for period='P2D', got {code!r}"
    )
    expected_message = (
        "1 validation error detected: Value 'P2D' at 'period' failed to satisfy constraint: "
        "Member must satisfy enum value set: [P1D, PT1H, PT5M]"
    )
    assert message == expected_message, (message, expected_message)

    valid = cgp.list_profile_times(
        profilingGroupName=name, startTime=start, endTime=end, period="PT1H"
    )
    assert "profileTimes" in valid, (
        f"expected 'profileTimes' in the response for a valid period='PT1H', got keys "
        f"{sorted(valid.keys())!r}"
    )


def _error_code(fn):
    """Call fn(); return its ClientError code. An unexpected SUCCESS raises, because an
    over-permissive target accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
