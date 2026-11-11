"""task-definition-container-definitions-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "task-definition-container-definitions-round-trip"
GROUP = "state"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterTaskDefinition preserves container-level fields (port mappings,
    environment variables, resource limits) exactly on DescribeTaskDefinition."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-fam-")

    container_def = {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "essential": True,
        "cpu": 128,
        "memory": 256,
        "portMappings": [{"containerPort": 8080, "protocol": "tcp"}],
        "environment": [{"name": "FOO", "value": "bar"}, {"name": "BAZ", "value": "qux"}],
        "command": ["sleep", "60"],
    }

    registered = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[container_def],
    )["taskDefinition"]
    arn = registered["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _cleanup_task_def(ecs, arn))

    described = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    assert described["family"] == family, f"expected family {family!r}, got {described['family']!r}"
    assert described["cpu"] == "256", f"expected task-level cpu '256', got {described['cpu']!r}"
    assert described["memory"] == "512", f"expected task-level memory '512', got {described['memory']!r}"
    assert described["networkMode"] == "awsvpc", f"expected networkMode 'awsvpc', got {described['networkMode']!r}"

    containers = described["containerDefinitions"]
    assert len(containers) == 1, f"expected 1 container definition, got {len(containers)}"
    container = containers[0]
    assert container["name"] == "app", f"expected container name 'app', got {container['name']!r}"
    assert container["image"] == container_def["image"], (
        f"expected image {container_def['image']!r}, got {container['image']!r}"
    )
    assert container["essential"] is True, f"expected essential True, got {container['essential']!r}"
    assert container["cpu"] == 128, f"expected container cpu 128, got {container['cpu']!r}"
    assert container["memory"] == 256, f"expected container memory 256, got {container['memory']!r}"
    assert container["command"] == ["sleep", "60"], f"expected command ['sleep', '60'], got {container['command']!r}"
    assert container["portMappings"][0]["containerPort"] == 8080, (
        f"expected containerPort 8080, got {container['portMappings'][0]['containerPort']!r}"
    )
    assert container["portMappings"][0]["protocol"] == "tcp", (
        f"expected protocol 'tcp', got {container['portMappings'][0]['protocol']!r}"
    )

    env = {e["name"]: e["value"] for e in container["environment"]}
    assert env == {"FOO": "bar", "BAZ": "qux"}, f"environment round-trip mismatch: {env}"


def _cleanup_task_def(ecs, arn):
    try:
        ecs.deregister_task_definition(taskDefinition=arn)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted"))
        ):
            raise
    ecs.delete_task_definitions(taskDefinitions=[arn])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
