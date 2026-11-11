"""update-schedule-target-role-deleted-succeeds."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-schedule-target-role-deleted-succeeds"
GROUP = "error-semantics"
SERVICES = ["scheduler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSchedule does not validate that its target role still exists: after the role is
    deleted, updating the schedule with the dangling RoleArn succeeds and applies; assumability
    is checked only at invocation.
    """
    scheduler = ctx.client("scheduler")
    iam = ctx.client("iam")
    _, queue_arn = _create_queue(ctx)
    role_name, role_arn = _create_scheduler_role(ctx, [queue_arn])

    name = ctx.unique_name("sim2real-sched-")
    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=name,
        Description="original-desc",
        ScheduleExpression="rate(2 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={"Arn": queue_arn, "RoleArn": role_arn},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=name))

    # Break exactly one thing: delete the role the schedule still references.
    _delete_role(iam, role_name)

    # Prove the role is actually gone -- not merely that delete_role returned
    # 200 -- via an independent read, before leaning on that premise below.
    role_gone = _error(lambda: iam.get_role(RoleName=role_name))
    assert role_gone.get("Code") == "NoSuchEntity", (
        f"expected the deleted role {role_name!r} to read back as gone (NoSuchEntity), "
        f"got {role_gone.get('Code')!r}"
    )
    expected_role_message = f"The role with name {role_name} cannot be found."
    assert role_gone.get("Message") == expected_role_message, (
        f"expected GetRole message {expected_role_message!r}, got {role_gone.get('Message')!r}"
    )

    # A just-deleted role can stay assumable while IAM propagates; wait until CreateSchedule refuses
    # it, so the update's success cannot rest on a still-live role.
    _wait_role_refused(ctx, scheduler, queue_arn, role_arn)

    # UpdateSchedule referencing the now-deleted role succeeds -- no eager
    # re-validation of target-role existence at the control-plane layer.
    try:
        scheduler.update_schedule(
            Name=name,
            Description="updated-desc-with-dangling-role",
            ScheduleExpression="rate(2 minutes)",
            FlexibleTimeWindow={"Mode": "OFF"},
            State="ENABLED",
            Target={"Arn": queue_arn, "RoleArn": role_arn},
        )
    except ClientError as exc:
        raise AssertionError(
            f"expected UpdateSchedule to succeed despite a deleted target role, got "
            f"{exc.response.get('Error', {}).get('Code')!r}"
        ) from exc

    # effect present: the update DID apply, dangling role reference and all.
    desc = scheduler.get_schedule(Name=name)
    assert desc["Description"] == "updated-desc-with-dangling-role", (
        f"expected Description 'updated-desc-with-dangling-role', got {desc['Description']!r}"
    )
    assert desc["State"] == "ENABLED", f"expected State 'ENABLED', got {desc['State']!r}"
    assert desc["Target"]["RoleArn"] == role_arn, (
        f"expected Target.RoleArn {role_arn!r} (unchanged, dangling), got {desc['Target']['RoleArn']!r}"
    )

    # Repointing at a role that DOES exist also succeeds, confirming the
    # schedule is not stuck in some rejected/invalid state after the dangling
    # update -- it is a fully ordinary, further-updatable schedule.
    _, new_role_arn = _create_scheduler_role(ctx, [queue_arn])
    _update_schedule_retrying(
        ctx,
        scheduler,
        Name=name,
        Description="updated-desc-2",
        ScheduleExpression="rate(2 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={"Arn": queue_arn, "RoleArn": new_role_arn},
    )
    desc2 = scheduler.get_schedule(Name=name)
    assert desc2["Description"] == "updated-desc-2", (
        f"expected Description 'updated-desc-2', got {desc2['Description']!r}"
    )
    assert desc2["Target"]["RoleArn"] == new_role_arn, (
        f"expected Target.RoleArn {new_role_arn!r}, got {desc2['Target']['RoleArn']!r}"
    )





def _error(fn):
    """The botocore Error dict (Code, Message) a call raised. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-q-"), tags={"sim2real:managed": "true"}
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
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    policy_name = ctx.unique_name("sim2real-sched-pol-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": list(allowed_queue_arns)}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    return role_name, role_arn


def _delete_role(iam, role_name):
    """Delete a role and its inline policies; safe to call even if already gone."""
    try:
        for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _deadline(ctx, timeout_s: float) -> float:
    """Monotonic deadline ``timeout_s`` ahead, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))


def _wait_role_refused(ctx, scheduler, queue_arn, role_arn, timeout_s=240.0):
    """Poll a throwaway DISABLED CreateSchedule with *role_arn* until Scheduler refuses the role."""
    started = time.monotonic()
    deadline = _deadline(ctx, timeout_s)
    while True:
        probe = ctx.unique_name("sim2real-sched-probe-")
        try:
            scheduler.create_schedule(
                Name=probe,
                ScheduleExpression="rate(1 hour)",
                FlexibleTimeWindow={"Mode": "OFF"},
                State="DISABLED",
                Target={"Arn": queue_arn, "RoleArn": role_arn},
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "ValidationException":
                return
            raise
        ctx.on_cleanup(lambda n=probe: _delete_schedule_if_present(scheduler, n))
        scheduler.delete_schedule(Name=probe)
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"CreateSchedule still accepted the deleted role {role_arn!r} "
                f"{time.monotonic() - started:.0f}s after DeleteRole"
            )
        time.sleep(2)


def _delete_schedule_if_present(scheduler, name):
    try:
        scheduler.delete_schedule(Name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_schedule_retrying(ctx, scheduler, **kwargs):
    """IAM role trust is eventually consistent; retry CreateSchedule briefly."""
    last_exc = None
    deadline = _deadline(ctx, 45.0)
    while time.monotonic() < deadline:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as e:
            last_exc = e
            if e.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException"):
                time.sleep(2.0)
                continue
            raise
    raise last_exc


def _update_schedule_retrying(ctx, scheduler, **kwargs):
    last_exc = None
    deadline = _deadline(ctx, 45.0)
    while time.monotonic() < deadline:
        try:
            return scheduler.update_schedule(**kwargs)
        except ClientError as e:
            last_exc = e
            if e.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException", "ResourceNotFoundException"):
                time.sleep(2.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
