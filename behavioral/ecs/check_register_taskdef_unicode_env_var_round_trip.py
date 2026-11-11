"""register-taskdef-unicode-env-var-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "register-taskdef-unicode-env-var-round-trip"
GROUP = "state-machine"
SERVICES = ["ecs"]

_UNICODE_VALUE = "héllo wörld 日本語テスト 🎉 Ñoño Кириллица"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A multi-byte unicode env var value registered on a task definition is
    returned byte-identical (no mangling/re-encoding) on DescribeTaskDefinition."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-td-unicode-")

    register_resp = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "unicode-container",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "memory": 128,
                "essential": True,
                "environment": [
                    {"name": "UNICODE_VAL", "value": _UNICODE_VALUE},
                ],
            }
        ],
    )
    task_def_arn = register_resp["taskDefinition"]["taskDefinitionArn"]

    def _cleanup():
        ecs.deregister_task_definition(taskDefinition=task_def_arn)
        ecs.delete_task_definitions(taskDefinitions=[task_def_arn])

    ctx.on_cleanup(_cleanup)

    # The register response itself should already carry the exact value back.
    register_env = register_resp["taskDefinition"]["containerDefinitions"][0]["environment"]
    register_by_name = {e["name"]: e["value"] for e in register_env}
    assert "UNICODE_VAL" in register_by_name, (
        f"RegisterTaskDefinition response dropped UNICODE_VAL entirely: {register_env!r}"
    )
    register_value = register_by_name["UNICODE_VAL"]
    assert register_value == _UNICODE_VALUE, (
        f"RegisterTaskDefinition response mangled unicode env value: "
        f"expected {_UNICODE_VALUE!r}, got {register_value!r}"
    )

    describe_resp = ecs.describe_task_definition(taskDefinition=task_def_arn)
    describe_env = describe_resp["taskDefinition"]["containerDefinitions"][0]["environment"]
    describe_by_name = {e["name"]: e["value"] for e in describe_env}
    assert "UNICODE_VAL" in describe_by_name, (
        f"DescribeTaskDefinition response dropped UNICODE_VAL entirely: {describe_env!r}"
    )
    describe_value = describe_by_name["UNICODE_VAL"]
    assert describe_value == _UNICODE_VALUE, (
        f"DescribeTaskDefinition returned a different unicode env value: "
        f"expected {_UNICODE_VALUE!r}, got {describe_value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
