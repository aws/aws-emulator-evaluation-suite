"""list-taskdefs-vs-families-prefix-semantics."""
from __future__ import annotations

from behavioral_harness import tags

DEFAULT_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "amazonlinux:2",
        "cpu": 10,
        "memory": 64,
        "essential": True,
    }
]

CHECK = "list-taskdefs-vs-families-prefix-semantics"
GROUP = 'task-definition'
SERVICES = ['ecs']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTaskDefinitions familyPrefix matches a family name exactly, while
    ListTaskDefinitionFamilies familyPrefix matches by true string prefix, so a family
    that only shares that string prefix is excluded by one call and included by the other."""
    ecs = ctx.client("ecs")
    base = ctx.unique_name("sim2real-behav-ecs-taskdef-")
    primary_family = f"{base}-primary"
    decoy_family = f"{base}-primary-two"

    rev1 = ecs.register_task_definition(
        family=primary_family, containerDefinitions=DEFAULT_CONTAINER_DEFS
    )["taskDefinition"]
    ctx.on_cleanup(lambda a=rev1["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=rev1["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))
    rev2 = ecs.register_task_definition(
        family=primary_family, containerDefinitions=DEFAULT_CONTAINER_DEFS
    )["taskDefinition"]
    ctx.on_cleanup(lambda a=rev2["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=rev2["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))

    decoy = ecs.register_task_definition(
        family=decoy_family, containerDefinitions=DEFAULT_CONTAINER_DEFS
    )["taskDefinition"]
    ctx.on_cleanup(lambda a=decoy["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=decoy["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))

    exact_pages = ecs.get_paginator("list_task_definitions").paginate(familyPrefix=primary_family)
    exact_arns = [a for page in exact_pages for a in page["taskDefinitionArns"]]
    assert exact_arns == [rev1["taskDefinitionArn"], rev2["taskDefinitionArn"]], (
        f"ListTaskDefinitions familyPrefix={primary_family!r} must match exactly that family's "
        f"two revisions in ascending order, and not the decoy family {decoy_family!r}, which "
        f"shares the {primary_family!r} string as a true prefix; got {exact_arns!r}"
    )

    short_pages = ecs.get_paginator("list_task_definitions").paginate(familyPrefix=base)
    short_arns = [a for page in short_pages for a in page["taskDefinitionArns"]]
    assert short_arns == [], (
        f"ListTaskDefinitions familyPrefix={base!r} is a true string prefix of both "
        f"{primary_family!r} and {decoy_family!r}, not the full name of either family, so it "
        f"must match no task definitions; got {short_arns!r}"
    )

    family_pages = ecs.get_paginator("list_task_definition_families").paginate(familyPrefix=base)
    families = sorted(f for page in family_pages for f in page["families"])
    assert families == sorted([primary_family, decoy_family]), (
        f"ListTaskDefinitionFamilies familyPrefix={base!r} matches by true string prefix, so it "
        f"must return exactly [{primary_family!r}, {decoy_family!r}]; got {families!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
