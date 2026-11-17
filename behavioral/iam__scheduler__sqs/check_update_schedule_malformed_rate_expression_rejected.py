"""update-schedule-malformed-rate-expression-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-schedule-malformed-rate-expression-rejected"
GROUP = "expression-validation"
SERVICES = ["iam", "scheduler", "sqs"]

_ASSUME_ROLE_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "scheduler.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}

_MALFORMED_RATE_REJECTED = (
    "ValidationException",
    "Invalid Schedule Expression rate(five minutes).",
)


def _delivery_role(ctx):
    """Create a role Scheduler can assume, able to send to any SQS queue the check made."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sched-exec-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_ASSUME_ROLE_TRUST),
    )["Role"]

    def _remove_role():
        for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_remove_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-scheduler-send-to-queue",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
        }),
    )
    return role["Arn"]


def _queue_arn(ctx, name):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name)["QueueUrl"]

    def _remove_queue():
        try:
            sqs.delete_queue(QueueUrl=url)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
                raise

    ctx.on_cleanup(_remove_queue)
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_with_role_wait(sch, *, deadline_s: float = 90.0, interval_s: float = 5.0, **kwargs):
    """CreateSchedule validates the execution role at call time; retry only while IAM has not
    yet propagated a freshly created role, never any other failure."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return sch.create_schedule(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume the role" in message and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def expect_error(fn, code, message):
    """Call fn(); assert it raises exactly (code, message). An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        got_code = exc.response["Error"]["Code"]
        got_message = exc.response["Error"].get("Message")
        assert got_code == code, f"expected error code {code!r}, got {got_code!r}"
        assert got_message == message, f"expected message {message!r}, got {got_message!r}"
        return
    raise AssertionError(f"expected the call to be refused with {code}, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateSchedule rejects a malformed rate expression and leaves the prior expression in
    place; the same request with a syntactically valid expression succeeds.
    """
    sch = ctx.client("scheduler")
    role_arn = _delivery_role(ctx)
    name = ctx.unique_name("sim2real-behav-ratefix-")
    queue_arn = _queue_arn(ctx, ctx.unique_name("sim2real-behav-sched-ratefix-"))

    _create_with_role_wait(
        sch,
        Name=name,
        ScheduleExpression="rate(5 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": queue_arn, "RoleArn": role_arn},
        State="ENABLED",
        Description="steady cadence",
    )
    ctx.on_cleanup(lambda: sch.delete_schedule(Name=name))

    expect_error(
        lambda: sch.update_schedule(
            Name=name,
            ScheduleExpression="rate(five minutes)",
            FlexibleTimeWindow={"Mode": "OFF"},
            Target={"Arn": queue_arn, "RoleArn": role_arn},
            State="ENABLED",
            Description="steady cadence",
        ),
        *_MALFORMED_RATE_REJECTED,
    )

    unchanged = sch.get_schedule(Name=name)
    assert unchanged["ScheduleExpression"] == "rate(5 minutes)", (
        f"a refused UpdateSchedule must not change ScheduleExpression; expected 'rate(5 minutes)', "
        f"got {unchanged['ScheduleExpression']!r}"
    )

    sch.update_schedule(
        Name=name,
        ScheduleExpression="rate(5 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": queue_arn, "RoleArn": role_arn},
        State="ENABLED",
        Description="legal neighbour",
    )
    control = sch.get_schedule(Name=name)
    assert control["Description"] == "legal neighbour", (
        f"the legal neighbour request (same expression, valid syntax) must succeed; "
        f"expected Description 'legal neighbour', got {control.get('Description')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
