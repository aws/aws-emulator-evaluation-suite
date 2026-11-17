"""register-task-definition-rejects-unrecognized-device-permission."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-task-definition-rejects-unrecognized-device-permission"
GROUP = "overly-permissive"
SERVICES = ["ecs"]

_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"

_UNRECOGNIZED_DEVICE_PERMISSION = (
    "ClientException",
    "Invalid permission: execute for device /dev/null",
)


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn`` raises exactly ``(code, message)``; raises on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        got_code = exc.response["Error"]["Code"]
        got_message = exc.response["Error"]["Message"]
        assert got_code == code, f"expected error code {code!r}, got {got_code!r} ({got_message!r})"
        assert got_message == message, f"expected message {message!r}, got {got_message!r}"
        return
    raise AssertionError(f"expected {code!r} ({message!r}) but the call succeeded: {result!r}")


def _no_revision(ecs, family: str) -> None:
    """Assert no task definition revision exists for ``family``."""
    arns = ecs.list_task_definitions(familyPrefix=family)["taskDefinitionArns"]
    assert arns == [], f"a revision was created for refused family {family!r}: {arns!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterTaskDefinition rejects a device permission outside read/write/mknod on an
    EC2-compatible container, creating no revision; the same device with only read succeeds."""
    ecs = ctx.client("ecs")

    bad_family = ctx.unique_name("sim2real-behav-ecs-devperm-bad-")
    expect_error(
        lambda: ecs.register_task_definition(
            family=bad_family,
            containerDefinitions=[{
                "name": "app",
                "image": _IMAGE,
                "memory": 128,
                "essential": True,
                "linuxParameters": {
                    "devices": [{
                        "hostPath": "/dev/null",
                        "containerPath": "/dev/null",
                        "permissions": ["execute"],
                    }],
                },
            }],
        ),
        *_UNRECOGNIZED_DEVICE_PERMISSION,
    )
    _no_revision(ecs, bad_family)

    # Positive control: the device's legal neighbour, a modeled permission, registers.
    good_family = ctx.unique_name("sim2real-behav-ecs-devperm-good-")
    registered = ecs.register_task_definition(
        family=good_family,
        containerDefinitions=[{
            "name": "app",
            "image": _IMAGE,
            "memory": 128,
            "essential": True,
            "linuxParameters": {
                "devices": [{
                    "hostPath": "/dev/null",
                    "containerPath": "/dev/null",
                    "permissions": ["read"],
                }],
            },
        }],
    )["taskDefinition"]
    arn = registered["taskDefinitionArn"]
    ctx.on_cleanup(lambda a=arn: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=arn: ecs.deregister_task_definition(taskDefinition=a))

    described = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    perms = described["containerDefinitions"][0]["linuxParameters"]["devices"][0]["permissions"]
    assert perms == ["read"], f"expected permissions == ['read'], got {perms!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
