"""create-schedule-ecs-target-task-count-below-minimum-rejected."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-ecs-target-task-count-below-minimum-rejected"
GROUP = "negative-classes"
SERVICES = ["iam", "scheduler"]

_ROLE_PROPAGATION = (
    "ValidationException",
    "The execution role you provide must allow AWS EventBridge Scheduler to assume the role.",
)


def _scheduler_role(ctx, iam):
    """An IAM role trusting scheduler.amazonaws.com, with a policy to run ECS tasks."""
    role_name = ctx.unique_name("sim2real-behav-sched-ecs-tc-role-")
    assume_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "scheduler.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    created = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=assume_doc)

    def _del_role():
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_del_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="run-ecs-task",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["ecs:RunTask", "iam:PassRole"], "Resource": "*"}],
        }),
    )
    return created["Role"]["Arn"]


def _retry_role_propagation(fn, *, deadline_s=60.0):
    """IAM role trust for the ECS target propagates to the scheduler service asynchronously."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
            if got != _ROLE_PROPAGATION or time.monotonic() > deadline:
                raise
            time.sleep(3.0)


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


_TASK_COUNT_TOO_LOW = (
    "ValidationException",
    "1 validation error detected: Value '0' at 'target.ecsParameters.taskCount' failed to satisfy "
    "constraint: Member must have value greater than or equal to 1",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSchedule rejects an ECS target with EcsParameters.TaskCount below its minimum of 1
    with the exact constraint message naming target.ecsParameters.taskCount, and the schedule
    name it was refused under does not exist; TaskCount at the minimum of 1 is accepted.
    """
    iam = ctx.client("iam")
    sch = ctx.client("scheduler")
    sch_unvalidated = ctx.client("scheduler", config=Config(parameter_validation=False))
    role_arn = _scheduler_role(ctx, iam)

    cluster_arn = f"arn:aws:ecs:{ctx.region}:{ctx.account}:cluster/sim2real-behav-ecstc-cluster"
    taskdef_arn = f"arn:aws:ecs:{ctx.region}:{ctx.account}:task-definition/sim2real-behav-ecstc-taskdef:1"

    def _target(task_count):
        return {
            "Arn": cluster_arn,
            "RoleArn": role_arn,
            "EcsParameters": {"TaskDefinitionArn": taskdef_arn, "TaskCount": task_count},
        }

    rejected_name = ctx.unique_name("sim2real-behav-ecstc-rejected-")
    expect_error(
        lambda: _retry_role_propagation(lambda: sch_unvalidated.create_schedule(
            Name=rejected_name,
            ScheduleExpression="rate(1 day)",
            FlexibleTimeWindow={"Mode": "OFF"},
            State="DISABLED",
            Target=_target(0),
        )),
        *_TASK_COUNT_TOO_LOW,
        undo=lambda created: ctx.on_cleanup(lambda: sch.delete_schedule(Name=rejected_name)),
    )

    code = None
    try:
        sch.get_schedule(Name=rejected_name)
    except ClientError as exc:
        code = exc.response["Error"].get("Code")
        message = exc.response["Error"].get("Message")
    assert code == "ResourceNotFoundException", (
        f"GetSchedule of the rejected name returned code {code!r}, expected ResourceNotFoundException"
    )
    assert message == f"Schedule {rejected_name} does not exist.", (
        f"GetSchedule of the rejected name said {message!r}"
    )

    control_name = ctx.unique_name("sim2real-behav-ecstc-control-")
    _retry_role_propagation(lambda: sch.create_schedule(
        Name=control_name,
        ScheduleExpression="rate(1 day)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target=_target(1),
    ))
    ctx.on_cleanup(lambda: sch.delete_schedule(Name=control_name))
    control = sch.get_schedule(Name=control_name)
    control_count = control["Target"]["EcsParameters"]["TaskCount"]
    assert control_count == 1, f"the minimum TaskCount of 1 round-tripped as {control_count!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
