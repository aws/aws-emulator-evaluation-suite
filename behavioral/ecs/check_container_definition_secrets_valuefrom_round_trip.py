"""container-definition-secrets-valuefrom-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "container-definition-secrets-valuefrom-round-trip"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterTaskDefinition preserves a secrets[].valueFrom ARN containing special characters exactly."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-ecs-secrets-")

    # A Secrets Manager ARN with a JSON-key suffix and the full range of characters that
    # can legally appear in a secret name/ARN: '/', '_', '+', '=', '.', '@', '-', ':'.
    value_from = (
        f"arn:aws:secretsmanager:{ctx.region}:123456789012:"
        "secret:my/app-config_v2.1+test=copy@prod-AbCdEf:SOME_JSON_KEY::"
    )
    secrets = [{"name": "DB_PASSWORD", "valueFrom": value_from}]

    # RegisterTaskDefinition requires an executionRoleArn whenever a container specifies
    # `secrets` (the task execution role is what the ECS agent would assume to fetch them).
    # RegisterTaskDefinition only validates the ARN's shape, not that the role exists, so a
    # well-formed placeholder in this account is sufficient to exercise the round trip.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    execution_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-behav-ecs-exec-role"

    register_resp = ecs.register_task_definition(
        family=family,
        executionRoleArn=execution_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "amazonlinux:2",
                "memory": 128,
                "essential": True,
                "secrets": secrets,
            }
        ],
    )
    task_def_arn = register_resp["taskDefinition"]["taskDefinitionArn"]

    def _cleanup():
        ecs.deregister_task_definition(taskDefinition=task_def_arn)
        ecs.delete_task_definitions(taskDefinitions=[task_def_arn])

    ctx.on_cleanup(_cleanup)

    registered_secrets = register_resp["taskDefinition"]["containerDefinitions"][0]["secrets"]
    assert registered_secrets == secrets, (
        f"secrets valueFrom not preserved on RegisterTaskDefinition's own response: "
        f"{registered_secrets!r} != {secrets!r}"
    )

    described = ecs.describe_task_definition(taskDefinition=task_def_arn)["taskDefinition"]
    returned_secrets = described["containerDefinitions"][0]["secrets"]

    assert returned_secrets == secrets, f"secrets valueFrom not preserved: {returned_secrets!r} != {secrets!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
