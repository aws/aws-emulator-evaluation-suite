"""op-contract-describeTaskDefinition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describeTaskDefinition"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTaskDefinition returns the exact registered contents and rejects an unknown family."""
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
                "environment": [{"name": "SIM2REAL_KEY", "value": "sim2real-value-42"}],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    arn = reg["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))

    resp = ecs.describe_task_definition(taskDefinition=family, include=["TAGS"])
    td = resp["taskDefinition"]
    assert td["taskDefinitionArn"] == arn, f"expected arn {arn!r}, got {td['taskDefinitionArn']!r}"
    assert td["status"] == "ACTIVE", f"expected status ACTIVE, got {td['status']!r}"
    assert td["family"] == family, f"expected family {family!r}, got {td['family']!r}"
    assert len(td["containerDefinitions"]) == 1, (
        f"expected 1 container definition, got {len(td['containerDefinitions'])}"
    )
    container = td["containerDefinitions"][0]
    assert container["image"] == "public.ecr.aws/amazonlinux/amazonlinux:2023", (
        f"expected the registered image, got {container['image']!r}"
    )
    assert container["cpu"] == 128, f"expected cpu 128, got {container['cpu']!r}"
    assert {"name": "SIM2REAL_KEY", "value": "sim2real-value-42"} in container["environment"], (
        f"expected the registered env var in {container['environment']!r}"
    )
    assert {"key": "sim2real", "value": "true"} in resp["tags"], (
        f"expected the registered tag in {resp['tags']!r}"
    )

    err, message = _error(
        lambda: ecs.describe_task_definition(taskDefinition="sim2real-no-such-family-xyz")
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
