"""delete-nonexistent-alarm-is-silently-idempotent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-nonexistent-alarm-is-silently-idempotent"
GROUP = 'alarms'
SERVICES = ['cloudwatch']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAlarms on a name that never existed succeeds, as does a repeat, and DescribeAlarms
    then lists no such alarm, although the model lists ResourceNotFound for DeleteAlarms."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-cwprobe-ghost-")

    # Any ClientError here propagates and fails the check: real CloudWatch accepts the call.
    cw.delete_alarms(AlarmNames=[alarm_name])

    # Repeating the delete is likewise a no-op, and the ghost never materializes.
    cw.delete_alarms(AlarmNames=[alarm_name])

    resp = cw.describe_alarms(AlarmNames=[alarm_name])
    assert resp.get("MetricAlarms", []) == [], "nonexistent alarm must not appear in DescribeAlarms"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
