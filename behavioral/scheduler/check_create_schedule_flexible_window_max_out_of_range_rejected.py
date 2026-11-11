"""create-schedule-flexible-window-max-out-of-range-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-schedule-flexible-window-max-out-of-range-rejected"
GROUP = "error-semantics"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSchedule with MaximumWindowInMinutes=1441 (valid range 1-1440) is rejected with
    ValidationException and persists nothing; the same request with 60 succeeds."""
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    scheduler = ctx.client("scheduler")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-fw-q-"),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    role_arn = _create_scheduler_role(ctx, iam)

    # Positive control: a valid MaximumWindowInMinutes succeeds.
    good_name = ctx.unique_name("sim2real-sched-fw-good-")
    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=good_name,
        ScheduleExpression="rate(1 hour)",
        FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 60},
        Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": "ok"},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=good_name))
    good = scheduler.get_schedule(Name=good_name)
    good_window = good["FlexibleTimeWindow"]["MaximumWindowInMinutes"]
    assert good_window == 60, f"expected the accepted schedule's window to be 60, got {good_window!r}"

    # Negative: out-of-range value is rejected.
    bad_name = ctx.unique_name("sim2real-sched-fw-bad-")
    code, message = _error_code(
        lambda: scheduler.create_schedule(
            Name=bad_name,
            ScheduleExpression="rate(1 hour)",
            FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 1441},
            Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": "bad"},
        )
    )
    assert code == "ValidationException", f"expected ValidationException for MaximumWindowInMinutes=1441, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '1441' at 'flexibleTimeWindow.maximumWindowInMinutes' "
        "failed to satisfy constraint: Member must have value less than or equal to 1440"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    from botocore.exceptions import ClientError

    try:
        scheduler.get_schedule(Name=bad_name)
        raise AssertionError("rejected schedule was persisted anyway")
    except ClientError as err:
        got_code = err.response["Error"]["Code"]
        assert got_code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for the never-created schedule, got {got_code!r}"
        )
        got_message = err.response["Error"].get("Message")
        assert got_message == f"Schedule {bad_name} does not exist.", (
            f"expected the not-found message for {bad_name!r}, got {got_message!r}"
        )


def _create_scheduler_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-sched-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-policy-")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_schedule_retrying(ctx, scheduler, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 30.0
    while True:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "ValidationException") and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _error_code(fn):
    """Call fn(); return its error (code, message). An unexpected success raises rather than
    being reported as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
