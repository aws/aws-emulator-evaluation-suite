"""concurrent-delete-schedule-race-one-wins-one-404."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-delete-schedule-race-one-wins-one-404"
GROUP = "concurrency"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two simultaneous DeleteSchedule calls for the same schedule yield exactly
    one success and one ResourceNotFoundException -- never two successes."""
    scheduler = ctx.client("scheduler")
    _, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, [queue_arn])

    name = ctx.unique_name("sim2real-sched-")
    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=name,
        ScheduleExpression="rate(2 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={"Arn": queue_arn, "RoleArn": role_arn},
    )
    # Deletion is the test itself -- no separate delete cleanup is registered
    # for the schedule (it would race against, or duplicate, the assertions below).

    def _delete():
        try:
            scheduler.delete_schedule(Name=name)
            return ("ok", None)
        except ClientError as e:
            return ("error", e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [f.result() for f in [pool.submit(_delete), pool.submit(_delete)]]

    oks = [r for r in results if r[0] == "ok"]
    errors = [r for r in results if r[0] == "error"]

    assert len(oks) == 1, f"expected exactly one successful delete, got {results}"
    assert len(errors) == 1, f"expected exactly one failed delete, got {results}"
    assert errors[0][1] == "ResourceNotFoundException", (
        f"expected the losing delete to fail with ResourceNotFoundException, got {errors[0][1]}"
    )
    expected_message = f"Schedule {name} does not exist."
    assert errors[0][2] == expected_message, (
        f"expected losing-delete message {expected_message!r}, got {errors[0][2]!r}"
    )

    # effect confirmed: the schedule is gone
    get_code, get_message = _error_code(lambda: scheduler.get_schedule(Name=name))
    assert get_code == "ResourceNotFoundException", (
        f"expected GetSchedule on the deleted schedule to fail with ResourceNotFoundException, got {get_code}"
    )
    assert get_message == expected_message, (
        f"expected GetSchedule message {expected_message!r}, got {get_message!r}"
    )


def _error_code(fn):
    """The AWS (code, message) raised by fn(), or a loud failure if it unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to be REFUSED but it succeeded, returning {result!r}")


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-q-"),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
