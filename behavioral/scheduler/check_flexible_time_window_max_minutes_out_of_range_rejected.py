"""flexible-time-window-max-minutes-out-of-range-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flexible-time-window-max-minutes-out-of-range-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MaximumWindowInMinutes above the allowed 1-1440 range is rejected; valid values still work."""
    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue_arn)
    group_name = _create_group(ctx)
    scheduler = ctx.client("scheduler")

    # Positive control: a valid, in-range flexible window succeeds.
    good_name = ctx.unique_name("sim2real-sched-flexok-")
    _retry_role_not_ready(lambda: scheduler.create_schedule(
        Name=good_name,
        GroupName=group_name,
        ScheduleExpression="rate(1 hour)",
        FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 5},
        Target={
            "Arn": queue_arn,
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": "control"}),
        },
    ))
    ctx.on_cleanup(lambda: _delete_schedule_safe(ctx, good_name, group_name))

    # Break exactly one thing: MaximumWindowInMinutes above the documented 1440 maximum.
    bad_name = ctx.unique_name("sim2real-sched-flexbad-")

    def _attempt_bad_create():
        scheduler.create_schedule(
            Name=bad_name,
            GroupName=group_name,
            ScheduleExpression="rate(1 hour)",
            FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 1441},
            Target={
                "Arn": queue_arn,
                "RoleArn": role_arn,
                "Input": json.dumps({"marker": "bad"}),
            },
        )

    code, message = _error(_attempt_bad_create)
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '1441' at 'flexibleTimeWindow.maximumWindowInMinutes' "
        "failed to satisfy constraint: Member must have value less than or equal to 1440"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected schedule was never persisted.
    not_found_code, not_found_message = _error(
        lambda: scheduler.get_schedule(Name=bad_name, GroupName=group_name)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"out-of-range create must not leave a schedule behind, got {not_found_code!r}"
    )
    assert not_found_message == f"Schedule {bad_name} does not exist.", (
        f"unexpected not-found message: {not_found_message!r}"
    )

    # Positive control still holds: the valid schedule exists with its requested window.
    good = scheduler.get_schedule(Name=good_name, GroupName=group_name)
    good_max = good["FlexibleTimeWindow"]["MaximumWindowInMinutes"]
    assert good_max == 5, f"expected the in-range positive control to keep MaximumWindowInMinutes=5, got {good_max!r}"


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting input real AWS rejects must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _retry_role_not_ready(fn, max_wait_s=90, interval_s=5):
    """Retry fn() while Scheduler reports the freshly-created execution role isn't usable yet
    (IAM trust-policy propagation delay), up to max_wait_s. Any other error is re-raised."""
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



_MANAGED_TAGS = {"sim2real:managed": "true"}
_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-q-"), tags=_MANAGED_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_scheduler_role(ctx, queue_arn):
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
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_MANAGED_TAGS_KV
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-policy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    _wait_for_role_ready(ctx, role["Arn"], queue_arn)
    return role["Arn"]


def _wait_for_role_ready(ctx, role_arn, queue_arn, max_wait_s=90, interval_s=5):
    """Probe with a throwaway schedule until Scheduler accepts the freshly-created execution
    role (IAM trust-policy propagation can lag CreateRole by tens of seconds)."""
    scheduler = ctx.client("scheduler")
    probe_name = ctx.unique_name("sim2real-sched-warmup-")
    deadline = time.monotonic() + max_wait_s
    while True:
        try:
            scheduler.create_schedule(
                Name=probe_name,
                GroupName="default",
                ScheduleExpression="rate(1 hour)",
                FlexibleTimeWindow={"Mode": "OFF"},
                State="DISABLED",
                Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": json.dumps({"marker": "warmup"})},
            )
            scheduler.delete_schedule(Name=probe_name, GroupName="default")
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume the role" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_group(ctx):
    scheduler = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-sched-grp-")
    scheduler.create_schedule_group(Name=name, Tags=_MANAGED_TAGS_KV)
    ctx.on_cleanup(lambda: _delete_group_safe(ctx, name))
    return name


def _delete_schedule_safe(ctx, name, group_name):
    scheduler = ctx.client("scheduler")
    try:
        scheduler.delete_schedule(Name=name, GroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_group_safe(ctx, name):
    scheduler = ctx.client("scheduler")
    try:
        scheduler.delete_schedule_group(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
