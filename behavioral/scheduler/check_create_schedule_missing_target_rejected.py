"""create-schedule-missing-target-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-missing-target-rejected"
GROUP = "error-semantics"
SERVICES = ["scheduler"]

_MANAGED_TAGS = {"sim2real:managed": "true"}
_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """CreateSchedule with the required Target parameter omitted entirely is
    rejected with ValidationException before any resource is created, while an
    otherwise-identical request that includes Target succeeds."""
    queue = _create_target_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue["arn"])
    scheduler = ctx.client("scheduler")

    # Positive control: an otherwise-identical request that includes Target
    # succeeds and is independently readable back. This proves the queue,
    # role and credentials are healthy, so the rejection below is specific to
    # the missing Target rather than a symptom of a broken prerequisite. The
    # retry absorbs IAM role/policy propagation delay with a bounded deadline
    # instead of an unconditional sleep.
    good_name = ctx.unique_name("sim2real-sched-withtarget-")
    resp = _create_schedule_retrying(
        scheduler,
        Name=good_name,
        ScheduleExpression="rate(1 hour)",
        Target={"Arn": queue["arn"], "RoleArn": role_arn},
        FlexibleTimeWindow={"Mode": "OFF"},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=good_name))
    assert resp["ScheduleArn"], "create_schedule with Target present returned no ScheduleArn"
    good = scheduler.get_schedule(Name=good_name)
    assert good["Target"]["Arn"] == queue["arn"], (
        f"expected persisted Target.Arn {queue['arn']!r}, got {good['Target'].get('Arn')!r}"
    )

    # botocore treats Target as a required top-level member and would refuse to
    # even build the request locally; disable local validation so the omission
    # is actually sent to the service and we observe the *server's* rejection.
    scheduler_raw = ctx.client("scheduler", config=Config(parameter_validation=False))

    bad_name = ctx.unique_name("sim2real-sched-notarget-")
    code, message = _error(
        lambda: scheduler_raw.create_schedule(
            Name=bad_name,
            ScheduleExpression="rate(1 hour)",
            FlexibleTimeWindow={"Mode": "OFF"},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = "1 validation error detected: Value null at 'target' failed to satisfy constraint: Member must not be null"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    got_code, got_message = _error(lambda: scheduler.get_schedule(Name=bad_name))
    assert got_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the never-created schedule, got {got_code}"
    )
    expected_missing = f"Schedule {bad_name} does not exist."
    assert got_message == expected_missing, f"expected message {expected_missing!r}, got {got_message!r}"


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


def _create_schedule_retrying(scheduler, timeout_s: float = 30.0, interval_s: float = 3.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "ValidationException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
