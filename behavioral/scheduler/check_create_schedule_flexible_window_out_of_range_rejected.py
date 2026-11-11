"""create-schedule-flexible-window-out-of-range-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-flexible-window-out-of-range-rejected"
GROUP = "error-semantics"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """A FlexibleTimeWindow.MaximumWindowInMinutes value outside the documented
    [1, 1440] range is rejected with ValidationException (distinct from omitting the
    field entirely), the schedule is never created, and an in-range value succeeds."""
    queue = _create_target_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue["arn"])

    scheduler = ctx.client("scheduler")
    _wait_for_role_ready(ctx, scheduler, role_arn, queue["arn"])

    bad_name = ctx.unique_name("sim2real-sched-badwin-")
    code, message = _error_code(
        lambda: scheduler.create_schedule(
            Name=bad_name,
            ScheduleExpression="rate(1 hour)",
            Target={"Arn": queue["arn"], "RoleArn": role_arn},
            FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 1441},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = (
        "1 validation error detected: Value '1441' at 'flexibleTimeWindow.maximumWindowInMinutes' "
        "failed to satisfy constraint: Member must have value less than or equal to 1440"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    not_found_code, not_found_message = _error_code(lambda: scheduler.get_schedule(Name=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"out-of-range create must not leave a schedule behind, got {not_found_code}"
    )
    assert not_found_message == f"Schedule {bad_name} does not exist.", (
        f"expected the not-found message for {bad_name!r}, got {not_found_message!r}"
    )

    good_name = ctx.unique_name("sim2real-sched-goodwin-")
    resp = _create_schedule_retrying(
        scheduler,
        Name=good_name,
        ScheduleExpression="rate(1 hour)",
        Target={"Arn": queue["arn"], "RoleArn": role_arn},
        FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 60},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=good_name))
    assert resp["ScheduleArn"]
    got = scheduler.get_schedule(Name=good_name)
    assert got["FlexibleTimeWindow"]["MaximumWindowInMinutes"] == 60


def _error_code(fn):
    """The AWS (code, message) raised by fn(), or a loud failure if it unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to be REFUSED but it succeeded, returning {result!r}")


def _create_target_queue(ctx: Any) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-q-"),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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


def _wait_for_role_ready(ctx: Any, scheduler, role_arn: str, queue_arn: str, max_wait_s: float = 90.0, interval_s: float = 5.0) -> None:
    """Probe with a throwaway schedule until Scheduler accepts the freshly-created
    execution role: IAM trust-policy propagation can lag CreateRole/PutRolePolicy by
    tens of seconds (documented eventual consistency), and this is a bounded retry on
    the specific "can't assume role" ValidationException rather than a blind sleep, so
    it never risks the out-of-range assertion below landing on a role-not-ready error."""
    probe_name = ctx.unique_name("sim2real-sched-warmup-")
    deadline = time.monotonic() + max_wait_s
    while True:
        try:
            scheduler.create_schedule(
                Name=probe_name,
                ScheduleExpression="rate(1 hour)",
                FlexibleTimeWindow={"Mode": "OFF"},
                State="DISABLED",
                Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": "warmup"},
            )
            scheduler.delete_schedule(Name=probe_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume" in msg.lower() and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_schedule_retrying(scheduler, timeout_s: float = 30.0, interval_s: float = 3.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
