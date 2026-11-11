"""container-environment-unicode-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "container-environment-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A container environment value with unicode, newlines, quotes and backslashes round-trips
    exactly through RegisterTaskDefinition and DescribeTaskDefinition: no normalization or truncation."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-envuni-")

    tricky_value = (
        'héllo wörld 日本語 🚀 line-one\nline-two\t"quoted" back\\slash '
        "emoji-family 👨‍👩‍👧 combining-\u0301-mark"
    )

    register = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "memory": 64,
                "essential": True,
                "environment": [{"name": "GREETING", "value": tricky_value}],
            }
        ],
    )
    task_def_arn = register["taskDefinition"]["taskDefinitionArn"]

    def _cleanup():
        ecs.deregister_task_definition(taskDefinition=task_def_arn)
        ecs.delete_task_definitions(taskDefinitions=[task_def_arn])

    ctx.on_cleanup(_cleanup)

    register_env = register["taskDefinition"]["containerDefinitions"][0]["environment"]
    register_by_name = {e["name"]: e["value"] for e in register_env}
    assert register_by_name.get("GREETING") == tricky_value, (
        f"RegisterTaskDefinition response mangled the unicode env value: "
        f"expected {tricky_value!r}, got {register_by_name.get('GREETING')!r}"
    )

    described = ecs.describe_task_definition(taskDefinition=task_def_arn)
    env = described["taskDefinition"]["containerDefinitions"][0]["environment"]
    env_by_name = {e["name"]: e["value"] for e in env}
    assert env_by_name.get("GREETING") == tricky_value, (
        f"DescribeTaskDefinition returned a different unicode env value: "
        f"expected {tricky_value!r}, got {env_by_name.get('GREETING')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
