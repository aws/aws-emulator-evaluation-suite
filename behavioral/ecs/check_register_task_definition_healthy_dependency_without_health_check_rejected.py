"""register-task-definition-healthy-dependency-without-health-check-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-task-definition-healthy-dependency-without-health-check-rejected"
GROUP = "task-definition"
SERVICES = ["ecs"]

_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) raised by fn(). An unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _containers(*, sidecar_health_check: bool) -> list[dict]:
    sidecar = {
        "name": "sidecar",
        "image": _IMAGE,
        "essential": True,
        "command": ["sh", "-c", "sleep 300"],
    }
    if sidecar_health_check:
        sidecar["healthCheck"] = {
            "command": ["CMD-SHELL", "exit 0"],
            "interval": 30,
            "timeout": 5,
            "retries": 3,
            "startPeriod": 0,
        }
    app = {
        "name": "app",
        "image": _IMAGE,
        "essential": True,
        "command": ["sh", "-c", "sleep 300"],
        "dependsOn": [{"containerName": "sidecar", "condition": "HEALTHY"}],
    }
    return [sidecar, app]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterTaskDefinition refuses a HEALTHY dependsOn on a container with no healthCheck,
    leaving no revision listed; the identical pair with a healthCheck registers ACTIVE."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-ecs-dephc-")

    code, message = _error(
        lambda: ecs.register_task_definition(
            family=family,
            requiresCompatibilities=["FARGATE"],
            networkMode="awsvpc",
            cpu="256",
            memory="512",
            containerDefinitions=_containers(sidecar_health_check=False),
        )
    )
    assert code == "ClientException", f"expected ClientException, got {code}: {message!r}"
    want = "A dependency container with HEALTHY condition must have health check configured"
    assert message == want, f"unexpected message: {message!r}"

    arns = ecs.list_task_definitions(familyPrefix=family)["taskDefinitionArns"]
    assert arns == [], (
        f"refused registration must leave no revision of {family!r}, got {arns!r}"
    )

    td = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=_containers(sidecar_health_check=True),
    )["taskDefinition"]
    arn = td["taskDefinitionArn"]

    def _deregister_and_delete() -> None:
        try:
            ecs.deregister_task_definition(taskDefinition=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException":
                raise
        try:
            ecs.delete_task_definitions(taskDefinitions=[arn])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException":
                raise

    ctx.on_cleanup(_deregister_and_delete)

    assert td["status"] == "ACTIVE", f"the healthCheck-bearing pair must register ACTIVE, got {td['status']!r}"
    assert td["revision"] == 1, f"it is the family's first revision, got {td['revision']!r}"
    sidecar_def = next(c for c in td["containerDefinitions"] if c["name"] == "sidecar")
    assert sidecar_def.get("healthCheck", {}).get("command") == ["CMD-SHELL", "exit 0"], (
        f"the registered sidecar must carry its healthCheck, got {sidecar_def.get('healthCheck')!r}"
    )
    app_def = next(c for c in td["containerDefinitions"] if c["name"] == "app")
    assert app_def.get("dependsOn") == [{"containerName": "sidecar", "condition": "HEALTHY"}], (
        f"the registered app must carry its dependsOn, got {app_def.get('dependsOn')!r}"
    )

    arns_after = ecs.list_task_definitions(familyPrefix=family)["taskDefinitionArns"]
    assert arns_after == [arn], (
        f"the control's revision must be the only one listed for {family!r}, got {arns_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
