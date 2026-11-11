"""create-schedule-flexible-window-missing-max."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-flexible-window-missing-max"
GROUP = 'error-semantics'
SERVICES = ['scheduler']


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-fw-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return arn


def _create_scheduler_role(ctx, queue_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sched-fw-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "scheduler.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-fw-policy-")
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
    probe_name = ctx.unique_name("sim2real-sched-fw-warmup-")
    deadline = time.monotonic() + max_wait_s
    while True:
        try:
            scheduler.create_schedule(
                Name=probe_name,
                ScheduleExpression="rate(1 hour)",
                FlexibleTimeWindow={"Mode": "OFF"},
                State="DISABLED",
                Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": json.dumps({"marker": "warmup"})},
            )
            scheduler.delete_schedule(Name=probe_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume the role" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _flexible_window(mode="OFF", max_minutes=None):
    window = {"Mode": mode}
    if max_minutes is not None:
        window["MaximumWindowInMinutes"] = max_minutes
    return window


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """FlexibleTimeWindow Mode=FLEXIBLE requires MaximumWindowInMinutes: a value in range is
    accepted and persisted (positive control), but its absence raises ValidationException and
    the schedule is never persisted."""
    sch = ctx.client("scheduler")
    queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue_arn)

    # Positive control: FLEXIBLE with a valid MaximumWindowInMinutes is accepted and persisted,
    # so the negative below cannot be "rejects every FLEXIBLE window" in disguise.
    good_name = ctx.unique_name("sim2real-behav-sched-good-")
    sch.create_schedule(
        Name=good_name,
        ScheduleExpression="rate(5 minutes)",
        FlexibleTimeWindow=_flexible_window("FLEXIBLE", 15),
        Target={"Arn": queue_arn, "RoleArn": role_arn},
    )
    ctx.on_cleanup(lambda: sch.delete_schedule(Name=good_name))
    good = sch.get_schedule(Name=good_name)
    assert good["FlexibleTimeWindow"] == {"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 15}, (
        f"expected persisted FlexibleTimeWindow with MaximumWindowInMinutes=15, got {good['FlexibleTimeWindow']!r}"
    )

    # Negative: FLEXIBLE with no MaximumWindowInMinutes is rejected outright.
    bad_name = ctx.unique_name("sim2real-behav-sched-bad-")
    error = _client_error(lambda: sch.create_schedule(
        Name=bad_name,
        ScheduleExpression="rate(5 minutes)",
        FlexibleTimeWindow=_flexible_window("FLEXIBLE"),  # no MaximumWindowInMinutes
        Target={"Arn": queue_arn, "RoleArn": role_arn},
    ))
    assert error.get("Code") == "ValidationException", f"expected ValidationException, got {error!r}"
    expected_message = "MaximumWindowInMinutes must be provided when FlexibleTimeWindowMode is set to FLEXIBLE."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Independent read: the rejected schedule was never persisted.
    try:
        sch.get_schedule(Name=bad_name)
        raise AssertionError("rejected schedule was persisted anyway")
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException on the rejected name, got {exc.response['Error']!r}"
        )
        assert exc.response["Error"].get("Message") == f"Schedule {bad_name} does not exist.", (
            f"expected the not-found message for {bad_name!r}, got {exc.response['Error']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
