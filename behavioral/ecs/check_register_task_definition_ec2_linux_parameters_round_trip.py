"""register-task-definition-ec2-linux-parameters-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "register-task-definition-ec2-linux-parameters-round-trip"
GROUP = "representation"
SERVICES = ["ecs"]

_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterTaskDefinition accepts an EC2-compatible container adding the NET_ADMIN
    capability, a noexec/nosuid tmpfs mount and a read-only /dev/null device, and
    DescribeTaskDefinition reads back exactly those linuxParameters."""
    ecs = ctx.client("ecs")

    family = ctx.unique_name("sim2real-behav-ecs-ec2lp-")
    linux_parameters = {
        "capabilities": {"add": ["NET_ADMIN"]},
        "tmpfs": [{
            "containerPath": "/scratch",
            "size": 64,
            "mountOptions": ["noexec", "nosuid"],
        }],
        "devices": [{
            "hostPath": "/dev/null",
            "containerPath": "/dev/null",
            "permissions": ["read"],
        }],
    }
    registered = ecs.register_task_definition(
        family=family,
        containerDefinitions=[{
            "name": "app",
            "image": _IMAGE,
            "memory": 128,
            "essential": True,
            "linuxParameters": linux_parameters,
        }],
    )["taskDefinition"]
    arn = registered["taskDefinitionArn"]
    ctx.on_cleanup(lambda a=arn: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=arn: ecs.deregister_task_definition(taskDefinition=a))

    described = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    got = described["containerDefinitions"][0]["linuxParameters"]
    assert got["capabilities"]["add"] == ["NET_ADMIN"], (
        f"expected capabilities.add == ['NET_ADMIN'], got {got['capabilities']['add']!r}"
    )
    assert got["capabilities"].get("drop", []) == [], (
        f"expected no dropped capabilities, got {got['capabilities'].get('drop')!r}"
    )
    assert got["tmpfs"] == linux_parameters["tmpfs"], (
        f"expected tmpfs == {linux_parameters['tmpfs']!r}, got {got['tmpfs']!r}"
    )
    assert got["devices"] == linux_parameters["devices"], (
        f"expected devices == {linux_parameters['devices']!r}, got {got['devices']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
