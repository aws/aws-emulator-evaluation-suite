"""create-schedule-flexible-window-exceeds-max-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-flexible-window-exceeds-max-rejected"
GROUP = "error-semantics"
SERVICES = ["scheduler"]

_MANAGED_TAGS = {"sim2real:managed": "true"}
_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With Mode=FLEXIBLE, MaximumWindowInMinutes=1441 (ceiling 1440) is rejected server-side with
    ValidationException and persists nothing; an in-range schedule keeps its window of 5."""
    scheduler = ctx.client("scheduler")
    _, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, [queue_arn])

    good_name = ctx.unique_name("sim2real-sched-ok-")
    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=good_name,
        ScheduleExpression="rate(2 minutes)",
        FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 5},
        State="DISABLED",
        Target={"Arn": queue_arn, "RoleArn": role_arn},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=good_name))

    bad_name = ctx.unique_name("sim2real-sched-bad-")
    raised = False
    try:
        scheduler.create_schedule(
            Name=bad_name,
            ScheduleExpression="rate(2 minutes)",
            FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 1441},
            State="DISABLED",
            Target={"Arn": queue_arn, "RoleArn": role_arn},
        )
    except ClientError as e:
        raised = True
        # botocore validates only the shape's `min`, not its `max`, so the ceiling is a
        # server-side ValidationException, not a local ParamValidationError.
        code = e.response["Error"]["Code"]
        message = e.response["Error"]["Message"]
        assert code == "ValidationException", (
            f"expected ValidationException for MaximumWindowInMinutes=1441, got {code}: {message}"
        )
        expected_message = (
            "1 validation error detected: Value '1441' at 'flexibleTimeWindow.maximumWindowInMinutes' "
            "failed to satisfy constraint: Member must have value less than or equal to 1440"
        )
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    assert raised, "expected a server-side rejection for MaximumWindowInMinutes=1441 (max allowed is 1440)"

    # effect absent: nothing was created under the rejected name
    get_code, get_message = _error_code(lambda: scheduler.get_schedule(Name=bad_name))
    assert get_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {get_code}"
    assert get_message == f"Schedule {bad_name} does not exist.", (
        f"expected the not-found message for {bad_name!r}, got {get_message!r}"
    )

    # positive control still stands
    desc = scheduler.get_schedule(Name=good_name)
    actual_max = desc["FlexibleTimeWindow"]["MaximumWindowInMinutes"]
    assert actual_max == 5, f"expected the positive control's MaximumWindowInMinutes to remain 5, got {actual_max}"


def _error_code(fn):
    """The AWS (code, message) raised by fn(), or a loud failure if it unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to be REFUSED but it succeeded, returning {result!r}")


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-q-"), tags=_MANAGED_TAGS)["QueueUrl"]
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
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_MANAGED_TAGS_KV
    )["Role"]["Arn"]
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
