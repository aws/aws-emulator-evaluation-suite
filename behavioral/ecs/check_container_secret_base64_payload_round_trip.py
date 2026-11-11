"""container-secret-base64-payload-round-trip."""
from __future__ import annotations

import base64
import os

from behavioral_harness import tags

CHECK = "container-secret-base64-payload-round-trip"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A secrets `valueFrom` carrying a base64 payload in an ARN-shaped name round-trips byte-for-byte
    through RegisterTaskDefinition and DescribeTaskDefinition: ECS does not resolve it at registration."""
    ecs = ctx.client("ecs")
    sts = ctx.client("sts")
    family = ctx.unique_name("sim2real-ecs-secret-")

    raw_binary = bytes(range(256)) + os.urandom(32)
    b64_payload = base64.urlsafe_b64encode(raw_binary).decode("ascii").rstrip("=")
    account_id = sts.get_caller_identity()["Account"]
    value_from = f"arn:aws:secretsmanager:{ctx.region}:{account_id}:secret:sim2real-{b64_payload}"
    # RegisterTaskDefinition requires an executionRoleArn to be present whenever a
    # container specifies `secrets` (it validates the role's presence, not its
    # existence/permissions, at registration time -- resolution happens at RunTask).
    execution_role_arn = f"arn:aws:iam::{account_id}:role/ecsTaskExecutionRole"

    register = ecs.register_task_definition(
        family=family,
        executionRoleArn=execution_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "memory": 64,
                "essential": True,
                "secrets": [{"name": "MY_SECRET", "valueFrom": value_from}],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    task_def_arn = register["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=task_def_arn))
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[task_def_arn]))

    registered_secrets = register["taskDefinition"]["containerDefinitions"][0]["secrets"]
    assert registered_secrets[0]["valueFrom"] == value_from, (
        f"RegisterTaskDefinition's own response mangled valueFrom: "
        f"expected {value_from!r}, got {registered_secrets[0]['valueFrom']!r}"
    )

    described = ecs.describe_task_definition(taskDefinition=task_def_arn)["taskDefinition"]
    described_secrets = described["containerDefinitions"][0]["secrets"]
    assert len(described_secrets) == 1, (
        f"expected exactly 1 secret on the described task definition, got {len(described_secrets)}: {described_secrets!r}"
    )
    assert described_secrets[0]["name"] == "MY_SECRET", (
        f"expected secret name 'MY_SECRET', got {described_secrets[0]['name']!r}"
    )
    assert described_secrets[0]["valueFrom"] == value_from, (
        f"DescribeTaskDefinition did not round-trip the base64 payload: "
        f"expected {value_from!r}, got {described_secrets[0]['valueFrom']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
