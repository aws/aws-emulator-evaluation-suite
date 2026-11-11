"""create-schedule-malformed-rate-expression-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-malformed-rate-expression-rejected"
GROUP = "error-semantics"
SERVICES = ["scheduler"]

_MANAGED_TAGS = {"sim2real:managed": "true"}
_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """A syntactically invalid rate() expression is rejected with ValidationException and creates
    nothing, while an otherwise-identical valid rate(1 hour) schedule succeeds."""
    queue = _create_target_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue["arn"])

    # Local parameter validation is off so the malformed expression reaches the endpoint.
    scheduler = ctx.client("scheduler", config=Config(parameter_validation=False))

    # Positive control first: its bounded retry also absorbs IAM propagation lag before the
    # malformed call below.
    good_name = ctx.unique_name("sim2real-sched-goodrate-")
    resp = _create_schedule_retrying(
        scheduler,
        Name=good_name,
        ScheduleExpression="rate(1 hour)",
        Target={"Arn": queue["arn"], "RoleArn": role_arn},
        FlexibleTimeWindow={"Mode": "OFF"},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=good_name))
    assert resp["ScheduleArn"], f"create_schedule for {good_name!r} returned no ScheduleArn: {resp!r}"
    got = scheduler.get_schedule(Name=good_name)
    assert got["ScheduleExpression"] == "rate(1 hour)", (
        f"positive control {good_name!r} recorded ScheduleExpression "
        f"{got['ScheduleExpression']!r}, expected 'rate(1 hour)'"
    )

    bad_name = ctx.unique_name("sim2real-sched-badrate-")
    ctx.on_cleanup(lambda: _delete_schedule_ignore_missing(scheduler, bad_name))
    code, message = _error(
        lambda: scheduler.create_schedule(
            Name=bad_name,
            ScheduleExpression="rate(five minutes)",
            Target={"Arn": queue["arn"], "RoleArn": role_arn},
            FlexibleTimeWindow={"Mode": "OFF"},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = "Invalid Schedule Expression rate(five minutes)."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found_code, not_found_message = _error(lambda: scheduler.get_schedule(Name=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"malformed create must not leave a schedule behind, got {not_found_code}"
    )
    expected_missing = f"Schedule {bad_name} does not exist."
    assert not_found_message == expected_missing, (
        f"expected message {expected_missing!r}, got {not_found_message!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


def _delete_schedule_ignore_missing(scheduler, name: str) -> None:
    try:
        scheduler.delete_schedule(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_target_queue(ctx: Any) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-q-"), tags=_MANAGED_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_scheduler_role(ctx: Any, resource_arn: str) -> str:
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
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": resource_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_schedule_retrying(scheduler, timeout_s: float = 45.0, interval_s: float = 3.0, **kwargs):
    # New IAM roles are eventually consistent across services, so CreateSchedule can briefly
    # fail with these codes; retry them on a deadline.
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            retryable = code in ("ResourceNotFoundException", "ValidationException", "AccessDeniedException")
            if retryable and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
