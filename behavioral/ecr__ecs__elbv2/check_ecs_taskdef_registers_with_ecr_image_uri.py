"""ecs-taskdef-registers-with-ecr-image-uri."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-taskdef-registers-with-ecr-image-uri"
GROUP = "resource-reference"
SERVICES = ["ecr", "ecs", "elbv2"]


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecsxref-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _register_task_definition_awaiting_role_propagation(
    ecs, deadline_s: float = 90.0, **kwargs
):
    """RegisterTaskDefinition, retried until a deadline while ECS rejects the freshly created
    executionRoleArn with ClientException because its trust has not yet propagated."""
    deadline = time.monotonic() + deadline_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return ecs.register_task_definition(**kwargs)["taskDefinition"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            message = exc.response.get("Error", {}).get("Message", "")
            if code == "ClientException" and "assume" in message.lower():
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise TimeoutError(
        f"executionRoleArn {kwargs.get('executionRoleArn')!r} did not become assumable "
        f"by ECS within {deadline_s}s: {last_exc}"
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTaskDefinition returns containerDefinitions[].image exactly as the ECR repository URI
    it was registered with, without rewriting or normalizing it."""
    ecr = ctx.client("ecr")
    ecs = ctx.client("ecs")

    repo_name = ctx.unique_name("sim2real-ecrref-")
    repo = ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}]
    )["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    image_uri = f"{repo['repositoryUri']}:latest"

    execution_role_arn = _create_execution_role(ctx)

    family = ctx.unique_name("sim2real-taskdef-")
    reg = _register_task_definition_awaiting_role_propagation(
        ecs,
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=execution_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": image_uri,
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    task_def_arn = reg["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    described = ecs.describe_task_definition(taskDefinition=task_def_arn)[
        "taskDefinition"
    ]
    containers = described["containerDefinitions"]
    assert len(containers) == 1, (
        f"expected exactly 1 container definition, got {len(containers)}"
    )
    assert containers[0]["image"] == image_uri, (
        f"expected stored image {image_uri!r}, got {containers[0]['image']!r}"
    )
    assert containers[0]["image"].startswith(repo["repositoryUri"]), (
        f"expected stored image {containers[0]['image']!r} to start with "
        f"repository URI {repo['repositoryUri']!r}"
    )


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
