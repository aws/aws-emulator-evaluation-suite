"""delete-alarms-nonexistent-name-no-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-alarms-nonexistent-name-no-error"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAlarms is idempotent for a name that never existed: it returns 200 and no alarm is created or left behind."""
    cw = ctx.client("cloudwatch")
    fake_name = ctx.unique_name("sim2real-cw-nosuchalarm-")

    before = cw.describe_alarms(AlarmNames=[fake_name])
    assert before["MetricAlarms"] == [] and before["CompositeAlarms"] == [], (
        f"precondition violated: a fresh unique alarm name already exists: {before}"
    )

    resp = cw.delete_alarms(AlarmNames=[fake_name])
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, resp["ResponseMetadata"]

    after = cw.describe_alarms(AlarmNames=[fake_name])
    assert after["MetricAlarms"] == [] and after["CompositeAlarms"] == [], (
        "deleting a nonexistent alarm name must not conjure a resource into existence"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
