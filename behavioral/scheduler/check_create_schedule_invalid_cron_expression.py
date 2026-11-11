"""create-schedule-invalid-cron-expression."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-invalid-cron-expression"
GROUP = 'error-semantics'
SERVICES = ['scheduler']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """A syntactically invalid cron() expression is rejected with ValidationException and creates
    nothing, while an otherwise-identical valid cron() schedule succeeds and is left intact."""
    queue = _create_target_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue["arn"])
    scheduler = ctx.client("scheduler")

    good_name = ctx.unique_name("sim2real-sched-goodcron-")
    resp = _create_schedule_retrying(
        scheduler,
        Name=good_name,
        ScheduleExpression="cron(0 12 * * ? *)",
        Target={"Arn": queue["arn"], "RoleArn": role_arn},
        FlexibleTimeWindow={"Mode": "OFF"},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=good_name))
    assert resp["ScheduleArn"], "positive control: valid cron() expression must create a schedule"

    bad_name = ctx.unique_name("sim2real-sched-badcron-")
    code, message = _error(
        lambda: scheduler.create_schedule(
            Name=bad_name,
            ScheduleExpression="cron(not a valid cron)",
            Target={"Arn": queue["arn"], "RoleArn": role_arn},
            FlexibleTimeWindow={"Mode": "OFF"},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = "Invalid Schedule Expression cron(not a valid cron)."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found_code, not_found_message = _error(lambda: scheduler.get_schedule(Name=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"malformed create must not leave a schedule behind, got {not_found_code}"
    )
    expected_missing = f"Schedule {bad_name} does not exist."
    assert not_found_message == expected_missing, (
        f"expected message {expected_missing!r}, got {not_found_message!r}"
    )

    got = scheduler.get_schedule(Name=good_name)
    assert got["ScheduleExpression"] == "cron(0 12 * * ? *)", (
        "positive control must still stand after the rejected create"
    )


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


def _create_target_queue(ctx: Any) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_scheduler_role(ctx: Any, resource_arn: str) -> str:
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
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
    """IAM role trust is eventually consistent; retry the initial create briefly."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ValidationException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
