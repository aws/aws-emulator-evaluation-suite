"""schedule-flexible-time-window-out-of-range-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "schedule-flexible-time-window-out-of-range-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSchedule rejects a FlexibleTimeWindow.MaximumWindowInMinutes value above
    the documented 1-1440 range with ValidationException, the schedule is never
    created, and an otherwise-identical request with an in-range value succeeds."""
    scheduler = ctx.client("scheduler")

    target = _create_sqs_queue(ctx, "sim2real-behav-flexrange-tgt-")
    role_arn = _create_scheduler_role(
        ctx,
        "sim2real-behav-flexrange-role-",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": target["arn"]}],
    )
    base_target = {"Arn": target["arn"], "RoleArn": role_arn, "Input": "flex-range-probe"}

    rejected_name = ctx.unique_name("sim2real-behav-flexrange-bad-")
    code, message = _error(
        lambda: _retry_role_not_ready(
            lambda: scheduler.create_schedule(
                Name=rejected_name,
                ScheduleExpression="rate(1 day)",
                FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 1441},
                State="ENABLED",
                Target=base_target,
            )
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '1441' at 'flexibleTimeWindow.maximumWindowInMinutes' "
        "failed to satisfy constraint: Member must have value less than or equal to 1440"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected schedule must not exist.
    not_found_code, not_found_message = _error(lambda: scheduler.get_schedule(Name=rejected_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {not_found_code!r}"
    )
    assert not_found_message == f"Schedule {rejected_name} does not exist.", (
        f"unexpected not-found message: {not_found_message!r}"
    )

    # Positive control: an otherwise-identical request with a valid window succeeds.
    accepted_name = ctx.unique_name("sim2real-behav-flexrange-good-")
    _retry_role_not_ready(
        lambda: scheduler.create_schedule(
            Name=accepted_name,
            ScheduleExpression="rate(1 day)",
            FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 1440},
            State="ENABLED",
            Target=base_target,
        )
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=accepted_name))
    described = scheduler.get_schedule(Name=accepted_name)
    assert described["FlexibleTimeWindow"]["MaximumWindowInMinutes"] == 1440


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an
    emulator accepting input real AWS rejects never reads as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_sqs_queue(ctx, prefix: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name(prefix)
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _retry_role_not_ready(fn, max_wait_s: float = 90.0, interval_s: float = 5.0):
    """Retry fn() while Scheduler reports the freshly-created execution role isn't
    assumable yet (IAM trust-policy propagation lag). Any other error, including the
    out-of-range ValidationException under test, is raised immediately."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + max_wait_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume the role" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
