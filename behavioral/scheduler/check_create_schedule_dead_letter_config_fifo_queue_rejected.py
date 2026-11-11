"""create-schedule-dead-letter-config-fifo-queue-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-dead-letter-config-fifo-queue-rejected"
GROUP = "error-semantics"
SERVICES = ["scheduler"]

_CREATE_TIMEOUT_S = 180


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
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": resource_arn}],
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
    """A Target DeadLetterConfig pointing at a FIFO SQS queue is rejected because its ARN's
    '.fifo' suffix fails the field's ARN pattern constraint; a standard queue in the same
    position is accepted and round-trips."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")

    target_name = ctx.unique_name("sim2real-sched-target-")
    target_url = sqs.create_queue(QueueName=target_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=target_url))
    target_arn = sqs.get_queue_attributes(
        QueueUrl=target_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    fifo_name = ctx.unique_name("sim2real-sched-dlq-") + ".fifo"
    fifo_url = sqs.create_queue(
        QueueName=fifo_name, Attributes={"FifoQueue": "true"}, tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=fifo_url))
    fifo_arn = sqs.get_queue_attributes(
        QueueUrl=fifo_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    standard_name = ctx.unique_name("sim2real-sched-dlq-")
    standard_url = sqs.create_queue(QueueName=standard_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=standard_url))
    standard_arn = sqs.get_queue_attributes(
        QueueUrl=standard_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    role_arn = _create_scheduler_role(ctx, target_arn)

    # Positive control first, so the role is assumable before the refusal is asserted.
    good_name = ctx.unique_name("sim2real-sched-stddlq-")
    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=good_name,
        ScheduleExpression="rate(1 hour)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": target_arn, "RoleArn": role_arn, "DeadLetterConfig": {"Arn": standard_arn}},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=good_name))

    got = scheduler.get_schedule(Name=good_name)
    assert got["Target"]["DeadLetterConfig"]["Arn"] == standard_arn, (
        "positive control: a standard-queue DeadLetterConfig must round-trip, got "
        f"{got['Target'].get('DeadLetterConfig')!r}"
    )

    bad_name = ctx.unique_name("sim2real-sched-fifodlq-")
    code, message = _error(
        lambda: scheduler.create_schedule(
            Name=bad_name,
            ScheduleExpression="rate(1 hour)",
            FlexibleTimeWindow={"Mode": "OFF"},
            Target={"Arn": target_arn, "RoleArn": role_arn, "DeadLetterConfig": {"Arn": fifo_arn}},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    pattern = r"arn:aws[a-z-]*:sqs:[a-z0-9\-]+:\d{12}:[a-zA-Z0-9\-_]+"
    expected = (
        f"1 validation error detected: Value '{fifo_arn}' at "
        f"'target.deadLetterConfig.arn' failed to satisfy constraint: "
        f"Member must satisfy regular expression pattern: {pattern}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found_code, _ = _error(lambda: scheduler.get_schedule(Name=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"a refused create must not leave a schedule behind, got {not_found_code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
