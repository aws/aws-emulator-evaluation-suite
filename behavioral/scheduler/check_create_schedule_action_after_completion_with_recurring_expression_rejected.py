"""create-schedule-action-after-completion-with-recurring-expression-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "create-schedule-action-after-completion-with-recurring-expression-rejected"
GROUP = "error-semantics"
SERVICES = ["scheduler"]

_MANAGED_TAGS = {"sim2real:managed": "true"}
_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ActionAfterCompletion DELETE is accepted on a recurring schedule; unknown values are refused.

    The rate() schedule with an EndDate reads back DELETE; ActionAfterCompletion='ARCHIVE' fails
    ValidationException with the enum-constraint message and GetSchedule then reports not found.
    """
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    scheduler = ctx.client("scheduler")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-aac-q-"), tags=_MANAGED_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    role_arn = _create_scheduler_role(ctx, iam)

    # Positive control: ActionAfterCompletion=DELETE on a *recurring* schedule (with an
    # EndDate, so the setting is meaningful) is accepted, not rejected.
    end_date = datetime.now(timezone.utc) + timedelta(days=365)
    good_name = ctx.unique_name("sim2real-sched-aac-good-")
    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=good_name,
        ScheduleExpression="rate(1 hour)",
        ScheduleExpressionTimezone="UTC",
        EndDate=end_date,
        ActionAfterCompletion="DELETE",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": "ok"},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=good_name))
    good = scheduler.get_schedule(Name=good_name)
    assert good["ActionAfterCompletion"] == "DELETE", (
        f"expected DELETE on the recurring schedule, got {good.get('ActionAfterCompletion')!r}"
    )

    # Negative: an unrecognized ActionAfterCompletion enum value is rejected outright.
    bad_name = ctx.unique_name("sim2real-sched-aac-bad-")
    code, message = _error_code(
        lambda: scheduler.create_schedule(
            Name=bad_name,
            ScheduleExpression="rate(1 hour)",
            ActionAfterCompletion="ARCHIVE",
            FlexibleTimeWindow={"Mode": "OFF"},
            Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": "bad"},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value 'ARCHIVE' at 'actionAfterCompletion' failed to satisfy "
        "constraint: Member must satisfy enum value set: [DELETE, NONE]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    from botocore.exceptions import ClientError

    try:
        scheduler.get_schedule(Name=bad_name)
        raise AssertionError("rejected schedule was persisted anyway")
    except ClientError as err:
        got_code = err.response["Error"]["Code"]
        assert got_code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for the never-created schedule, got {got_code!r}"
        )
        got_message = err.response["Error"].get("Message")
        assert got_message == f"Schedule {bad_name} does not exist.", (
            f"expected the not-found message for {bad_name!r}, got {got_message!r}"
        )


def _create_scheduler_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-sched-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_MANAGED_TAGS_KV
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-policy-")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_schedule_retrying(ctx, scheduler, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 30.0
    while True:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "ValidationException") and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
