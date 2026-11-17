"""create-schedule-ecs-target-full-parameters-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-ecs-target-full-parameters-round-trip"
GROUP = "ecs-target"
SERVICES = ["scheduler", "iam"]

_ROLE_PROPAGATION_ERROR = (
    "ValidationException",
    "The execution role you provide must allow AWS EventBridge Scheduler to assume the role.",
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSchedule stores a full ECS target EcsParameters block and GetSchedule returns
    it back as the identical structure, compared as one value."""
    iam = ctx.client("iam")
    scheduler = ctx.client("scheduler")

    role_name = ctx.unique_name("sim2real-behav-sched-ecsrt-role-")
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

    schedule_name = ctx.unique_name("sim2real-behav-sched-ecsrt-")
    task_def_arn = (
        f"arn:aws:ecs:{ctx.region}:{ctx.account}:task-definition/{schedule_name}-taskdef:1"
    )
    cluster_arn = f"arn:aws:ecs:{ctx.region}:{ctx.account}:cluster/{schedule_name}-cluster"
    ecs_parameters = {
        "TaskDefinitionArn": task_def_arn,
        "TaskCount": 4,
        "LaunchType": "EC2",
        "NetworkConfiguration": {
            "awsvpcConfiguration": {
                "Subnets": [f"subnet-{schedule_name}aaaaaaa", f"subnet-{schedule_name}bbbbbbb"],
                "SecurityGroups": [f"sg-{schedule_name}ccccccc"],
            }
        },
        "Group": f"{schedule_name}-taskgroup",
        "PlacementConstraints": [
            {"type": "memberOf", "expression": "attribute:ecs.instance-type =~ t3.*"}
        ],
        "PlacementStrategy": [{"type": "binpack", "field": "memory"}],
        "EnableECSManagedTags": True,
        "EnableExecuteCommand": True,
        "PropagateTags": "TASK_DEFINITION",
        "ReferenceId": f"{schedule_name}-ref",
        "Tags": [{"team": "reporting"}, {"stage": "weekly"}],
    }
    target = {"Arn": cluster_arn, "RoleArn": role_arn, "EcsParameters": ecs_parameters}

    # IAM propagation: a trust policy that just granted scheduler.amazonaws.com assume
    # permission can take a few seconds to become visible to CreateSchedule's own check.
    deadline = time.monotonic() + 60
    while True:
        try:
            scheduler.create_schedule(
                Name=schedule_name,
                State="DISABLED",
                ScheduleExpression="rate(1 day)",
                FlexibleTimeWindow={"Mode": "OFF"},
                Target=target,
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
            if (code, message) == _ROLE_PROPAGATION_ERROR and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(_teardown(lambda: scheduler.delete_schedule(Name=schedule_name), "ResourceNotFoundException"))

    got = scheduler.get_schedule(Name=schedule_name)
    assert got["Target"]["EcsParameters"] == ecs_parameters, (
        f"GetSchedule EcsParameters {got['Target']['EcsParameters']!r} "
        f"does not match the submitted block {ecs_parameters!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
