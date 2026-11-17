"""create-schedule-ecs-target-assign-public-ip-with-ec2-launch-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-ecs-target-assign-public-ip-with-ec2-launch-type-rejected"
GROUP = "ecs-target"
SERVICES = ["scheduler", "iam"]

_ROLE_PROPAGATION_ERROR = (
    "ValidationException",
    "The execution role you provide must allow AWS EventBridge Scheduler to assume the role.",
)
_ASSIGN_PUBLIC_IP_REJECTED = (
    "ValidationException",
    "Parameter AssignPublicIp for the target is not supported when launch type is EC2",
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, except on ``not_found`` codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_with_role_propagation_retry(fn, deadline):
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
            if (code, message) == _ROLE_PROPAGATION_ERROR and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _error_pair(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSchedule rejects an ECS target with AssignPublicIp ENABLED when LaunchType is EC2,
    with no schedule created, while the same target with AssignPublicIp DISABLED succeeds and
    round-trips."""
    iam = ctx.client("iam")
    scheduler = ctx.client("scheduler")

    role_name = ctx.unique_name("sim2real-behav-sched-ecsip-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "scheduler.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    def _ecs_params(subnet_prefix, assign_public_ip):
        params = {
            "TaskDefinitionArn": (
                f"arn:aws:ecs:{ctx.region}:{ctx.account}:task-definition/{subnet_prefix}-taskdef:1"
            ),
            "LaunchType": "EC2",
            "NetworkConfiguration": {
                "awsvpcConfiguration": {"Subnets": [f"subnet-{subnet_prefix}aaaaaaa"]}
            },
        }
        if assign_public_ip is not None:
            params["NetworkConfiguration"]["awsvpcConfiguration"]["AssignPublicIp"] = assign_public_ip
        return params

    def _target(subnet_prefix, assign_public_ip):
        return {
            "Arn": f"arn:aws:ecs:{ctx.region}:{ctx.account}:cluster/{subnet_prefix}-cluster",
            "RoleArn": role_arn,
            "EcsParameters": _ecs_params(subnet_prefix, assign_public_ip),
        }

    deadline = time.monotonic() + 60
    rejected_name = ctx.unique_name("sim2real-behav-sched-ecsip-rej-")
    code, message = _error_pair(
        lambda: _create_with_role_propagation_retry(
            lambda: scheduler.create_schedule(
                Name=rejected_name,
                State="DISABLED",
                ScheduleExpression="rate(1 day)",
                FlexibleTimeWindow={"Mode": "OFF"},
                Target=_target(rejected_name, "ENABLED"),
            ),
            deadline,
        )
    )
    assert (code, message) == _ASSIGN_PUBLIC_IP_REJECTED, (
        f"expected {_ASSIGN_PUBLIC_IP_REJECTED}, got ({code!r}, {message!r})"
    )

    not_found_code, not_found_message = _error_pair(
        lambda: scheduler.get_schedule(Name=rejected_name)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"the rejected call left a schedule behind: GetSchedule returned {not_found_code!r}"
    )
    assert not_found_message == f"Schedule {rejected_name} does not exist.", (
        f"unexpected GetSchedule message {not_found_message!r}"
    )

    accepted_name = ctx.unique_name("sim2real-behav-sched-ecsip-ok-")
    accepted_params = _ecs_params(accepted_name, "DISABLED")
    _create_with_role_propagation_retry(
        lambda: scheduler.create_schedule(
            Name=accepted_name,
            State="DISABLED",
            ScheduleExpression="rate(1 day)",
            FlexibleTimeWindow={"Mode": "OFF"},
            Target=_target(accepted_name, "DISABLED"),
        ),
        deadline,
    )
    ctx.on_cleanup(_teardown(lambda: scheduler.delete_schedule(Name=accepted_name), "ResourceNotFoundException"))

    got = scheduler.get_schedule(Name=accepted_name)
    assert got["Target"]["EcsParameters"] == accepted_params, (
        f"GetSchedule EcsParameters {got['Target']['EcsParameters']!r} "
        f"does not match the submitted block {accepted_params!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
