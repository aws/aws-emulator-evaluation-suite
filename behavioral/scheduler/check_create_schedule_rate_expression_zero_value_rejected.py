"""create-schedule-rate-expression-zero-value-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-rate-expression-zero-value-rejected"
GROUP = "error-semantics"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A rate() expression with a zero interval value is rejected as malformed
    input -- a distinct malformed-value class from an invalid cron field."""
    scheduler = ctx.client("scheduler")
    _, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, [queue_arn])

    good_name = ctx.unique_name("sim2real-sched-ok-")
    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=good_name,
        ScheduleExpression="rate(2 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={"Arn": queue_arn, "RoleArn": role_arn},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=good_name))

    bad_name = ctx.unique_name("sim2real-sched-bad-")
    code, message = _error(
        lambda: scheduler.create_schedule(
            Name=bad_name,
            ScheduleExpression="rate(0 minutes)",
            FlexibleTimeWindow={"Mode": "OFF"},
            State="DISABLED",
            Target={"Arn": queue_arn, "RoleArn": role_arn},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Invalid Schedule Expression rate(0 minutes)."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the malformed schedule was never created
    get_code, get_message = _error(lambda: scheduler.get_schedule(Name=bad_name))
    assert get_code == "ResourceNotFoundException", (
        f"zero-value rate() must not leave a schedule behind, got {get_code!r}"
    )
    expected_missing = f"Schedule {bad_name} does not exist."
    assert get_message == expected_missing, f"expected message {expected_missing!r}, got {get_message!r}"

    # positive control still stands
    desc = scheduler.get_schedule(Name=good_name)
    assert desc["ScheduleExpression"] == "rate(2 minutes)", (
        f"expected the positive control's expression to survive unchanged, got {desc['ScheduleExpression']!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_scheduler_role(ctx, allowed_queue_arns):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sched-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-pol-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": list(allowed_queue_arns)}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_schedule_retrying(ctx, scheduler, **kwargs):
    """IAM role trust is eventually consistent; retry CreateSchedule briefly."""
    import time

    last_exc = None
    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as e:
            last_exc = e
            if e.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException"):
                time.sleep(3.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
