"""create-schedule-client-token-reuse-conflict-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "create-schedule-client-token-reuse-conflict-rejected"
GROUP = "concurrency"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSchedule for an existing Name is rejected with ConflictException even for a
    byte-identical ClientToken replay, leaving the original untouched; after deletion the same
    call succeeds, so the conflict tracks Name uniqueness, not the token."""
    scheduler = ctx.client("scheduler")

    target = _create_sqs_queue(ctx, "sim2real-behav-token-tgt-")
    role_arn = _create_scheduler_role(
        ctx,
        "sim2real-behav-token-role-",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": target["arn"]}],
    )
    base_target = {"Arn": target["arn"], "RoleArn": role_arn, "Input": "token-probe"}

    schedule_name = ctx.unique_name("sim2real-behav-token-sched-")
    client_token = ctx.unique_name("sim2real-tok-")

    first = _create_schedule_with_role_propagation_retry(
        scheduler,
        Name=schedule_name,
        ClientToken=client_token,
        ScheduleExpression="rate(1 day)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Description="v1",
        Target=base_target,
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=schedule_name))
    original_arn = first["ScheduleArn"]

    # Break exactly one thing: reuse the same ClientToken with a different Description.
    conflict_message = f"Schedule {schedule_name} already exists."
    code, message = _error_code(
        lambda: scheduler.create_schedule(
            Name=schedule_name,
            ClientToken=client_token,
            ScheduleExpression="rate(1 day)",
            FlexibleTimeWindow={"Mode": "OFF"},
            State="ENABLED",
            Description="v2-should-be-rejected",
            Target=base_target,
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    assert message == conflict_message, f"expected message {conflict_message!r}, got {message!r}"

    # Effect absent: the original schedule's Description was not overwritten.
    described = scheduler.get_schedule(Name=schedule_name)
    assert described["Description"] == "v1", (
        f"expected Description to remain 'v1', got {described['Description']!r}"
    )

    # Empirically, even a byte-identical replay (same ClientToken, same every other
    # parameter) of an existing Name is ALSO rejected with ConflictException --
    # EventBridge Scheduler enforces Name uniqueness unconditionally rather than
    # special-casing a matching ClientToken as an idempotent no-op.
    replay_code, replay_message = _error_code(
        lambda: scheduler.create_schedule(
            Name=schedule_name,
            ClientToken=client_token,
            ScheduleExpression="rate(1 day)",
            FlexibleTimeWindow={"Mode": "OFF"},
            State="ENABLED",
            Description="v1",
            Target=base_target,
        )
    )
    assert replay_code == "ConflictException", f"expected ConflictException, got {replay_code!r}"
    assert replay_message == conflict_message, (
        f"expected message {conflict_message!r}, got {replay_message!r}"
    )

    # The original schedule (and its Arn) is still intact and untouched.
    still_there = scheduler.get_schedule(Name=schedule_name)
    assert still_there["Arn"] == original_arn, (
        f"expected Arn to remain {original_arn!r}, got {still_there['Arn']!r}"
    )
    assert still_there["Description"] == "v1", (
        f"expected Description to remain 'v1', got {still_there['Description']!r}"
    )

    # Once the blocking schedule is gone, the identical rejected call must succeed: the
    # conflict is Name uniqueness, not a ClientToken-keyed lock.
    scheduler.delete_schedule(Name=schedule_name)
    deleted_code, deleted_message = _error_code(lambda: scheduler.get_schedule(Name=schedule_name))
    assert deleted_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {deleted_code!r}"
    )
    assert deleted_message == f"Schedule {schedule_name} does not exist.", (
        f"expected the not-found message for {schedule_name!r}, got {deleted_message!r}"
    )

    recreated = scheduler.create_schedule(
        Name=schedule_name,
        ClientToken=client_token,
        ScheduleExpression="rate(1 day)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Description="v1",
        Target=base_target,
    )
    assert recreated["ScheduleArn"], "expected create to succeed once the conflicting Name is gone"

    final = scheduler.get_schedule(Name=schedule_name)
    assert final["Description"] == "v1", (
        f"expected restored Description to be 'v1', got {final['Description']!r}"
    )


def _error_code(fn):
    """The AWS (code, message) raised by fn(), or a loud failure if it unexpectedly SUCCEEDS."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to be REFUSED but it succeeded, returning {result!r}")


def _create_schedule_with_role_propagation_retry(scheduler, deadline_s: float = 30.0, **kwargs):
    """Scheduler checks it can assume the target role at CreateSchedule time, and IAM propagation
    lags by seconds; retry only that failure until the deadline, never any other error."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code != "ValidationException" or "assume" not in message.lower():
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _create_sqs_queue(ctx, prefix: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name(prefix)
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn, "name": name}


def _create_scheduler_role(ctx, prefix: str, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name(prefix)
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
