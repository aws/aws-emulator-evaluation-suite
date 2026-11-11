"""create-schedule-universal-target-read-only-action-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-universal-target-read-only-action-rejected"
GROUP = "error-semantics"
SERVICES = ["scheduler"]

_CREATE_TIMEOUT_S = 180
_READ_ONLY_ARN = "arn:aws:scheduler:::aws-sdk:sqs:getQueueUrl"


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


def _create_scheduler_role(ctx, resource_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sched-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "scheduler.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-pol-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["sqs:GetQueueUrl", "sqs:SendMessage"],
            "Resource": resource_arn,
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _create_schedule_retrying(ctx, scheduler, interval_s=3.0, **kwargs):
    """CreateSchedule, retried only while Scheduler cannot yet assume the fresh role."""
    timeout_s = _budget_s(ctx, _CREATE_TIMEOUT_S)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code != "ValidationException" or "assume the role" not in msg:
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"CreateSchedule could not assume the role for {timeout_s:.0f}s: {msg!r}"
                ) from exc
            time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A universal target naming a read-only SQS API action (getQueueUrl) is rejected at
    CreateSchedule, and the same target with a mutating action (sendMessage) is accepted."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")

    queue_name = ctx.unique_name("sim2real-sched-utp-")
    queue_url = sqs.create_queue(QueueName=queue_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    role_arn = _create_scheduler_role(ctx, queue_arn)

    # Positive control first, so the role is assumable before the refusal is asserted.
    good_name = ctx.unique_name("sim2real-sched-mutupt-")
    mutating_arn = "arn:aws:scheduler:::aws-sdk:sqs:sendMessage"
    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=good_name,
        ScheduleExpression="rate(1 hour)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={
            "Arn": mutating_arn,
            "RoleArn": role_arn,
            "Input": json.dumps({"QueueUrl": queue_url, "MessageBody": "sim2real"}),
        },
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=good_name))

    got = scheduler.get_schedule(Name=good_name)
    assert got["Target"]["Arn"] == mutating_arn, (
        f"positive control: expected Target.Arn {mutating_arn!r}, got {got['Target'].get('Arn')!r}"
    )

    bad_name = ctx.unique_name("sim2real-sched-routp-")
    code, message = _error(
        lambda: scheduler.create_schedule(
            Name=bad_name,
            ScheduleExpression="rate(1 hour)",
            FlexibleTimeWindow={"Mode": "OFF"},
            Target={
                "Arn": _READ_ONLY_ARN,
                "RoleArn": role_arn,
                "Input": json.dumps({"QueueName": queue_name}),
            },
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Invalid RequestJson provided. Reason getQueueUrl API is not supported."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found_code, _ = _error(lambda: scheduler.get_schedule(Name=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"a refused create must not leave a schedule behind, got {not_found_code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
