"""trial-component-timestamp-millisecond-precision-preserved."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trial-component-timestamp-millisecond-precision-preserved"
GROUP = "server-side"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A millisecond-precision StartTime/EndTime supplied on CreateTrialComponent is
    returned unchanged on DescribeTrialComponent, with no truncation to whole-second
    granularity."""
    sm = ctx.client("sagemaker")
    tc_name = ctx.unique_name("sim2real-tc-ts-")

    start_time = datetime(2023, 5, 17, 12, 34, 56, 789000, tzinfo=timezone.utc)
    end_time = start_time + timedelta(minutes=5, seconds=15, milliseconds=345)

    sm.create_trial_component(
        TrialComponentName=tc_name,
        StartTime=start_time,
        EndTime=end_time,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_tc_quiet(sm, tc_name))

    desc = sm.describe_trial_component(TrialComponentName=tc_name)

    assert desc["StartTime"] == start_time, (
        f"StartTime not preserved at millisecond precision: {desc['StartTime']!r} "
        f"!= {start_time!r}"
    )
    assert desc["EndTime"] == end_time, (
        f"EndTime not preserved at millisecond precision: {desc['EndTime']!r} != {end_time!r}"
    )
    # Explicitly confirm the sub-second component survived (not just coincidentally
    # rounded to the same second boundary).
    assert desc["StartTime"].microsecond == 789000
    assert desc["EndTime"].microsecond == end_time.microsecond


def _delete_tc_quiet(sm, tc_name: str) -> None:
    try:
        sm.delete_trial_component(TrialComponentName=tc_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
