"""register-task-definition-rejects-invalid-linux-parameters."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-task-definition-rejects-invalid-linux-parameters"
GROUP = "overly-permissive"
SERVICES = ["ecs"]

_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"

_CAP_PREFIXED_REFUSED = (
    "ClientException",
    "Unrecognized Linux capabilities in add: [CAP_SYS_ADMIN]",
)
_TMPFS_UPPERCASE_REFUSED = (
    "ClientException",
    "The NOEXEC tmpfs mount option specified is invalid.",
)
_DEVICES_ON_FARGATE_REFUSED = (
    "ClientException",
    "Fargate compatible task definitions do not support devices",
)
_FARGATE_CAP_NOT_SYSPTRACE_REFUSED = (
    "ClientException",
    "NET_ADMIN is not allowed on Fargate.",
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterTaskDefinition refuses a CAP_-prefixed capability, an uppercase tmpfs mount
    option, devices on a Fargate-compatible definition and a non-SYS_PTRACE Fargate capability,
    creating no revision; Fargate adding only SYS_PTRACE registers and reads back exactly."""
    ecs = ctx.client("ecs")

    cap_prefixed_family = ctx.unique_name("sim2real-behav-ecs-ltp-capprefix-")
    expect_error(
        lambda: ecs.register_task_definition(
            family=cap_prefixed_family,
            containerDefinitions=[{
                "name": "app",
                "image": _IMAGE,
                "memory": 128,
                "essential": True,
                "linuxParameters": {"capabilities": {"add": ["CAP_SYS_ADMIN"]}},
            }],
        ),
        *_CAP_PREFIXED_REFUSED,
    )
    _no_revision(ecs, cap_prefixed_family)

    tmpfs_family = ctx.unique_name("sim2real-behav-ecs-ltp-tmpfs-")
    expect_error(
        lambda: ecs.register_task_definition(
            family=tmpfs_family,
            containerDefinitions=[{
                "name": "app",
                "image": _IMAGE,
                "memory": 128,
                "essential": True,
                "linuxParameters": {
                    "tmpfs": [{"containerPath": "/tmp", "size": 64, "mountOptions": ["NOEXEC"]}]
                },
            }],
        ),
        *_TMPFS_UPPERCASE_REFUSED,
    )
    _no_revision(ecs, tmpfs_family)

    devices_family = ctx.unique_name("sim2real-behav-ecs-ltp-devices-")
    expect_error(
        lambda: ecs.register_task_definition(
            family=devices_family,
            requiresCompatibilities=["FARGATE"],
            networkMode="awsvpc",
            cpu="256",
            memory="512",
            containerDefinitions=[{
                "name": "app",
                "image": _IMAGE,
                "essential": True,
                "linuxParameters": {
                    "devices": [{"hostPath": "/dev/null", "containerPath": "/dev/null"}]
                },
            }],
        ),
        *_DEVICES_ON_FARGATE_REFUSED,
    )
    _no_revision(ecs, devices_family)

    fargate_cap_family = ctx.unique_name("sim2real-behav-ecs-ltp-fgcap-")
    expect_error(
        lambda: ecs.register_task_definition(
            family=fargate_cap_family,
            requiresCompatibilities=["FARGATE"],
            networkMode="awsvpc",
            cpu="256",
            memory="512",
            containerDefinitions=[{
                "name": "app",
                "image": _IMAGE,
                "essential": True,
                "linuxParameters": {"capabilities": {"add": ["NET_ADMIN"]}},
            }],
        ),
        *_FARGATE_CAP_NOT_SYSPTRACE_REFUSED,
    )
    _no_revision(ecs, fargate_cap_family)

    # Positive control: the same Fargate shape adding only the one permitted capability
    # registers and reads back exactly what was sent.
    positive_family = ctx.unique_name("sim2real-behav-ecs-ltp-sysptrace-")
    registered = ecs.register_task_definition(
        family=positive_family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[{
            "name": "app",
            "image": _IMAGE,
            "essential": True,
            "linuxParameters": {"capabilities": {"add": ["SYS_PTRACE"]}},
        }],
    )["taskDefinition"]
    arn = registered["taskDefinitionArn"]
    ctx.on_cleanup(lambda a=arn: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=arn: ecs.deregister_task_definition(taskDefinition=a))

    described = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    linux_params = described["containerDefinitions"][0]["linuxParameters"]
    assert linux_params["capabilities"]["add"] == ["SYS_PTRACE"], (
        f"expected capabilities.add == ['SYS_PTRACE'], got {linux_params['capabilities']['add']!r}"
    )
    assert linux_params["capabilities"].get("drop", []) == [], (
        f"expected no dropped capabilities, got {linux_params['capabilities'].get('drop')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
