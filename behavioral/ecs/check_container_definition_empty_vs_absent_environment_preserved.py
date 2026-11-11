"""container-definition-empty-vs-absent-environment-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "container-definition-empty-vs-absent-environment-preserved"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A container definition registered with environment [] and one registered without
    environment both describe environment as []."""
    ecs = ctx.client("ecs")
    family_explicit = ctx.unique_name("sim2real-ecs-envexplicit-")
    family_absent = ctx.unique_name("sim2real-ecs-envabsent-")

    arn_explicit = ecs.register_task_definition(
        family=family_explicit,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "c",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "environment": [],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]["taskDefinitionArn"]

    arn_absent = ecs.register_task_definition(
        family=family_absent,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {"name": "c", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023", "essential": True}
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]["taskDefinitionArn"]

    def _cleanup(arn):
        ecs.deregister_task_definition(taskDefinition=arn)
        ecs.delete_task_definitions(taskDefinitions=[arn])

    ctx.on_cleanup(lambda: _cleanup(arn_absent))
    ctx.on_cleanup(lambda: _cleanup(arn_explicit))

    container_explicit = ecs.describe_task_definition(taskDefinition=arn_explicit)["taskDefinition"][
        "containerDefinitions"
    ][0]
    container_absent = ecs.describe_task_definition(taskDefinition=arn_absent)["taskDefinition"][
        "containerDefinitions"
    ][0]

    assert "environment" in container_explicit, "explicit empty environment array was dropped entirely"
    assert container_explicit["environment"] == [], (
        f"explicit empty environment array was not preserved as []: {container_explicit['environment']!r}"
    )
    # Real AWS normalizes an omitted `environment` to an empty list on describe too — so the
    # two registration styles converge to the same wire representation. The fidelity contract
    # to check is that this normalization is exact and consistent, not that absence is
    # preserved as a distinct sentinel.
    assert container_absent.get("environment") == [], (
        "an omitted environment field should be normalized to an empty list on describe, "
        f"got: {container_absent.get('environment')!r}"
    )
    assert container_explicit["environment"] == container_absent["environment"], (
        "explicit-empty and omitted environment fields diverged after normalization: "
        f"{container_explicit['environment']!r} vs {container_absent['environment']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
