"""flexible-window-minutes-out-of-range-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flexible-window-minutes-out-of-range-rejected"
GROUP = "representation"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MaximumWindowInMinutes above the documented max of 1440 is rejected, not clamped."""
    scheduler = ctx.client("scheduler")

    queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue_arn)

    rejected_name = ctx.unique_name("sim2real-sched-")
    code, message = _error(
        lambda: _create_schedule_with_retry(
            scheduler,
            Name=rejected_name,
            ScheduleExpression="rate(1 day)",
            State="DISABLED",
            FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 1441},
            Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": "unused"},
        )
    )
    assert code == "ValidationException", (
        f"MaximumWindowInMinutes=1441 (above the 1440 ceiling) should be rejected with "
        f"ValidationException, got {code!r}"
    )
    expected_message = (
        "1 validation error detected: Value '1441' at 'flexibleTimeWindow.maximumWindowInMinutes' "
        "failed to satisfy constraint: Member must have value less than or equal to 1440"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no schedule was actually created under that name.
    not_found_code, not_found_message = _error(lambda: scheduler.get_schedule(Name=rejected_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"the rejected create must not leave a schedule behind, got {not_found_code!r}"
    )
    assert not_found_message == f"Schedule {rejected_name} does not exist.", (
        f"unexpected not-found message: {not_found_message!r}"
    )

    # Positive control in the same file: the boundary value itself (1440) is accepted.
    accepted_name = ctx.unique_name("sim2real-sched-")
    _create_schedule_with_retry(
        scheduler,
        Name=accepted_name,
        ScheduleExpression="rate(1 day)",
        State="DISABLED",
        FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 1440},
        Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": "unused"},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=accepted_name))
    fetched = scheduler.get_schedule(Name=accepted_name)
    assert fetched["FlexibleTimeWindow"]["MaximumWindowInMinutes"] == 1440, (
        f"the boundary value 1440 must round-trip exactly, got "
        f"{fetched['FlexibleTimeWindow']['MaximumWindowInMinutes']!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_scheduler_role(ctx, queue_arn):
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
    policy_name = ctx.unique_name("sim2real-sched-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_schedule_with_retry(scheduler, retries=10, delay=3, **kwargs):
    """IAM role trust is eventually consistent; CreateSchedule validates it synchronously.

    Retries on the transient "role not visible yet" flavor of ValidationException on any
    attempt -- any other ValidationException (including the out-of-range value under test)
    is left to propagate immediately.
    """
    last_exc = None
    for attempt in range(retries):
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationException":
                message = str(exc).lower()
                if ("role" in message or "assume" in message) and attempt < retries - 1:
                    last_exc = exc
                    time.sleep(delay)
                    continue
            raise
    raise last_exc



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
