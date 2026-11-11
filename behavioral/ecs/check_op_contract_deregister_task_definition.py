"""op-contract-deregisterTaskDefinition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-deregisterTaskDefinition"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterTaskDefinition flips ACTIVE->INACTIVE and rejects an unknown family:revision."""
    ecs = ctx.client("ecs")

    family = ctx.unique_name("sim2real-behav-td-")
    reg = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "cpu": 128,
                "memory": 128,
                "essential": True,
            }
        ],
    )
    td = reg["taskDefinition"]
    assert td["status"] == "ACTIVE", f"expected ACTIVE on register, got {td['status']}"
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))

    resp = ecs.deregister_task_definition(taskDefinition=arn)
    assert resp["taskDefinition"]["status"] == "INACTIVE", (
        f"expected INACTIVE after deregister, got {resp['taskDefinition']['status']}"
    )
    assert resp["taskDefinition"]["taskDefinitionArn"] == arn, (
        f"expected arn {arn}, got {resp['taskDefinition']['taskDefinitionArn']}"
    )

    described = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    assert described["status"] == "INACTIVE", (
        f"expected independent describe to read back INACTIVE, got {described['status']}"
    )

    err, message = _error(
        lambda: ecs.deregister_task_definition(taskDefinition="sim2real-nonexistent-family-xyz:9999")
    )
    assert err == "ClientException", f"expected ClientException, got {err}"
    expected_message = 'Unable to describe task definition.'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
