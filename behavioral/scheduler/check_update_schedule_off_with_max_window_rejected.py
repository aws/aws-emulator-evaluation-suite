"""update-schedule-off-with-max-window-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-schedule-off-with-max-window-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam", "scheduler", "sqs"]

_OFF_WITH_MAX = (
    "ValidationException",
    "MaximumWindowInMinutes must not be provided when FlexibleTimeWindowMode is set to OFF.",
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where only the resource's own not-found codes mean it is
    already gone; anything else is re-raised."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code: str, message: str) -> None:
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


def _create_queue(ctx, sqs, name: str) -> str:
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                              "AWS.SimpleQueueService.NonExistentQueue"))
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_scheduler_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
    assume_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "scheduler.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=assume_doc)["Role"]

    def _del_role() -> None:
        for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_teardown(_del_role, "NoSuchEntity"))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-scheduler-sqs-send",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
        }),
    )
    return role["Arn"]


def _create_schedule_with_role_retry(sch, *, deadline_s: float = 90.0, interval_s: float = 5.0, **kwargs):
    """CreateSchedule validates the role at call time, and IAM trust-policy propagation can lag
    CreateRole/PutRolePolicy by tens of seconds with no condition to poll; retry only that."""
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateSchedule naming Mode OFF together with MaximumWindowInMinutes is refused and
    leaves the schedule's prior update in place; the same request without the maximum succeeds.
    """
    iam = ctx.client("iam")
    sch = ctx.client("scheduler")
    sqs = ctx.client("sqs")

    role_arn = _create_scheduler_role(ctx, iam)
    queue_a_arn = _create_queue(ctx, sqs, ctx.unique_name("sim2real-behav-sched-qa-"))
    queue_b_arn = _create_queue(ctx, sqs, ctx.unique_name("sim2real-behav-sched-qb-"))

    name = ctx.unique_name("sim2real-behav-sched-")
    _create_schedule_with_role_retry(
        sch,
        Name=name,
        ScheduleExpression="rate(1 hour)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={"Arn": queue_a_arn, "RoleArn": role_arn},
        Description="d1",
    )
    ctx.on_cleanup(_teardown(lambda: sch.delete_schedule(Name=name), "ResourceNotFoundException"))

    update_payload = json.dumps({"detail": "second-target"})
    sch.update_schedule(
        Name=name,
        ScheduleExpression="rate(30 minutes)",
        FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 5},
        Target={"Arn": queue_b_arn, "RoleArn": role_arn, "Input": update_payload},
        State="DISABLED",
        Description="d2",
    )
    prior = sch.get_schedule(Name=name)
    prior_last_mod = prior["LastModificationDate"]

    expect_error(
        lambda: sch.update_schedule(
            Name=name,
            ScheduleExpression="rate(30 minutes)",
            FlexibleTimeWindow={"Mode": "OFF", "MaximumWindowInMinutes": 5},
            Target={"Arn": queue_b_arn, "RoleArn": role_arn, "Input": update_payload},
            State="DISABLED",
            Description="d2",
        ),
        *_OFF_WITH_MAX,
    )

    after_refusal = sch.get_schedule(Name=name)
    assert after_refusal["FlexibleTimeWindow"]["Mode"] == "FLEXIBLE", (
        f"the refused update must not change FlexibleTimeWindow.Mode; expected 'FLEXIBLE', "
        f"got {after_refusal['FlexibleTimeWindow']!r}"
    )
    assert after_refusal["FlexibleTimeWindow"]["MaximumWindowInMinutes"] == 5, (
        f"the refused update must not change MaximumWindowInMinutes; expected 5, "
        f"got {after_refusal['FlexibleTimeWindow'].get('MaximumWindowInMinutes')!r}"
    )
    assert after_refusal["ScheduleExpression"] == "rate(30 minutes)", (
        f"the refused update must not change ScheduleExpression; expected 'rate(30 minutes)', "
        f"got {after_refusal['ScheduleExpression']!r}"
    )
    assert after_refusal["Target"]["Arn"] == queue_b_arn, (
        f"the refused update must not change Target.Arn; expected {queue_b_arn!r}, "
        f"got {after_refusal['Target']['Arn']!r}"
    )
    assert after_refusal["LastModificationDate"] == prior_last_mod, (
        f"the refused update must not advance LastModificationDate past {prior_last_mod!r}, "
        f"got {after_refusal['LastModificationDate']!r}"
    )

    sch.update_schedule(
        Name=name,
        ScheduleExpression="rate(30 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": queue_b_arn, "RoleArn": role_arn, "Input": update_payload},
        State="DISABLED",
        Description="d2",
    )
    control = sch.get_schedule(Name=name)
    assert control["FlexibleTimeWindow"] == {"Mode": "OFF"}, (
        f"positive control: the legal neighbour (same request without the maximum) must "
        f"succeed with FlexibleTimeWindow {{'Mode': 'OFF'}}, got {control['FlexibleTimeWindow']!r}"
    )
    assert "MaximumWindowInMinutes" not in control["FlexibleTimeWindow"], (
        f"positive control: expected no MaximumWindowInMinutes for Mode OFF, "
        f"got {control['FlexibleTimeWindow']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
