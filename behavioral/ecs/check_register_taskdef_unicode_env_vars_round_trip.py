"""register-taskdef-unicode-env-vars-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "register-taskdef-unicode-env-vars-round-trip"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterTaskDefinition preserves unicode container environment variable values byte-identical on read-back."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-ecs-unicode-")

    environment = [
        {"name": "GREETING", "value": "こんにちは世界 🌍 héllo wörld Ω"},
        {"name": "MIXED_SCRIPT", "value": "Ключ_日本語_😀_naïve café"},
        {"name": "RTL_TEXT", "value": "مرحبا بالعالم"},
    ]

    register_resp = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "amazonlinux:2",
                "memory": 128,
                "essential": True,
                "environment": environment,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    task_def_arn = register_resp["taskDefinition"]["taskDefinitionArn"]

    def _cleanup():
        ecs.deregister_task_definition(taskDefinition=task_def_arn)
        ecs.delete_task_definitions(taskDefinitions=[task_def_arn])

    ctx.on_cleanup(_cleanup)

    # ECS does not guarantee list ORDER for environment variables on read-back, only that each
    # value is byte-identical, so compare by name rather than positionally.
    expected_by_name = {e["name"]: e["value"] for e in environment}

    register_env = register_resp["taskDefinition"]["containerDefinitions"][0]["environment"]
    register_by_name = {e["name"]: e["value"] for e in register_env}
    assert register_by_name == expected_by_name, (
        f"RegisterTaskDefinition response mangled unicode env vars: "
        f"{register_by_name!r} != {expected_by_name!r}"
    )

    described = ecs.describe_task_definition(taskDefinition=task_def_arn)
    returned_env = described["taskDefinition"]["containerDefinitions"][0]["environment"]
    returned_by_name = {e["name"]: e["value"] for e in returned_env}
    assert returned_by_name == expected_by_name, (
        f"DescribeTaskDefinition unicode env vars not preserved: "
        f"{returned_by_name!r} != {expected_by_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
