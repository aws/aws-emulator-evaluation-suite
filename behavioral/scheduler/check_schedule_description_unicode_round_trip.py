"""schedule-description-unicode-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "schedule-description-unicode-round-trip"
GROUP = "representation"
SERVICES = ["scheduler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode/emoji characters in a schedule Description survive CreateSchedule -> GetSchedule byte-for-byte."""
    scheduler = ctx.client("scheduler")
    role_arn = _create_scheduler_role(ctx)
    name = ctx.unique_name("sim2real-behav-sched-")
    description = "Test 🎉 emoji Ünïcode ↔ 中文 — café naïve résumé — русский текст"

    _create_schedule_with_retry(
        ctx,
        scheduler,
        Name=name,
        Description=description,
        ScheduleExpression="rate(1 day)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={
            "Arn": "arn:aws:sqs:" + ctx.region + ":000000000000:sim2real-nonexistent-placeholder",
            "RoleArn": role_arn,
        },
        State="DISABLED",
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=name))

    got = scheduler.get_schedule(Name=name)
    assert got["Description"] == description, (
        f"Description mismatch: wrote {description!r}, got {got['Description']!r}"
    )


def _create_scheduler_role(ctx) -> str:
    """Create a minimal IAM role trusted by scheduler.amazonaws.com (no target permissions needed)."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Role"]["Arn"]


def _create_schedule_with_retry(ctx, scheduler, **kwargs):
    """CreateSchedule can transiently reject a freshly-created RoleArn while IAM trust-policy
    propagation is still in flight -- surfaced either as ResourceNotFoundException or as a
    ValidationException whose message complains the role must allow EventBridge Scheduler to
    assume it. Retry briefly on those transient signatures only."""
    import time

    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return scheduler.create_schedule(**kwargs)
        except scheduler.exceptions.ResourceNotFoundException as exc:
            last_err = exc
            time.sleep(2.0)
        except scheduler.exceptions.ValidationException as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if "must allow" not in msg and "assume" not in msg:
                raise
            last_err = exc
            time.sleep(2.0)
    raise AssertionError(f"CreateSchedule kept failing on role propagation: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
