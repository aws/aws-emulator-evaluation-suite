"""schedule-target-input-unicode-payload-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "schedule-target-input-unicode-payload-round-trip"
GROUP = "representation"
SERVICES = ["scheduler"]

_UNICODE_INPUT = (
    '{"message": "h\u00e9llo w\u00f6rld \U0001f680 \u65e5\u672c\u8a9e",'
    ' "emoji": "\U0001f389\U0001f525\u2728", "arrow": "\u2192\u2190"}'
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A target Input JSON payload with unicode/emoji is returned byte-identical by GetSchedule."""
    scheduler = ctx.client("scheduler")
    account_id = _account_id(ctx)
    role_arn = _create_execution_role(ctx)
    name = ctx.unique_name("sim2real-behav-sched-")

    _create_schedule_with_retry(
        scheduler,
        Name=name,
        ScheduleExpression="rate(1 hour)",
        State="DISABLED",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=_fake_target(ctx, account_id, role_arn, _UNICODE_INPUT),
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=name))

    got = scheduler.get_schedule(Name=name)
    assert got["Target"]["Input"] == _UNICODE_INPUT, (
        f"unicode Input payload was mutated: {got['Target']['Input']!r} != {_UNICODE_INPUT!r}"
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_execution_role(ctx) -> str:
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "scheduler.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Role"]["Arn"]


def _create_schedule_with_retry(scheduler, **kwargs):
    import time

    from botocore.exceptions import ClientError

    deadline = time.time() + 45
    last_err = None
    while time.time() < deadline:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume" in message.lower():
                last_err = err
                time.sleep(3)
                continue
            raise
    raise last_err


def _fake_target(ctx, account_id: str, role_arn: str, input_payload: str) -> dict:
    # The target ARN need not resolve to a real queue for CreateSchedule to succeed, and
    # Input content is not validated at creation time (only format), but RoleArn's trust
    # policy IS validated: it must allow scheduler.amazonaws.com to assume it.
    return {
        "Arn": f"arn:aws:sqs:{ctx.region}:{account_id}:sim2real-behav-fake-queue",
        "RoleArn": role_arn,
        "Input": input_payload,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
