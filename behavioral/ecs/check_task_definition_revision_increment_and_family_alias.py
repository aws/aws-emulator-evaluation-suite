"""task-definition-revision-increment-and-family-alias."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "task-definition-revision-increment-and-family-alias"
GROUP = "state"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Registering successive revisions in a family increments revision numbers and the
    bare-family alias resolves to the latest ACTIVE revision."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-fam-")
    arns = []

    def _cleanup():
        for arn in arns:
            try:
                ecs.deregister_task_definition(taskDefinition=arn)
            except ClientError as exc:
                err = exc.response["Error"]
                if not (
                    err["Code"] == "ClientException"
                    and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted"))
                ):
                    raise
        if arns:
            ecs.delete_task_definitions(taskDefinitions=arns)

    ctx.on_cleanup(_cleanup)

    rev1 = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {"name": "app", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023", "essential": True}
        ],
    )["taskDefinition"]
    arns.append(rev1["taskDefinitionArn"])
    assert rev1["revision"] == 1, f"expected first revision 1, got {rev1['revision']}"
    assert rev1["status"] == "ACTIVE", f"expected status ACTIVE, got {rev1['status']}"

    rev2 = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="512",
        memory="1024",
        containerDefinitions=[
            {"name": "app", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023", "essential": True}
        ],
    )["taskDefinition"]
    arns.append(rev2["taskDefinitionArn"])
    assert rev2["revision"] == 2, f"expected revision 2, got {rev2['revision']}"

    families = ecs.list_task_definition_families(familyPrefix=family)["families"]
    assert family in families, f"expected family {family} in {families}"

    revisions = ecs.list_task_definitions(familyPrefix=family, sort="DESC")["taskDefinitionArns"]
    assert rev2["taskDefinitionArn"] in revisions and rev1["taskDefinitionArn"] in revisions, (
        f"expected both {rev1['taskDefinitionArn']} and {rev2['taskDefinitionArn']} in {revisions}"
    )
    assert revisions[0] == rev2["taskDefinitionArn"], (
        f"DESC sort should place latest revision first, got {revisions[0]}"
    )

    latest = ecs.describe_task_definition(taskDefinition=family)["taskDefinition"]
    assert latest["revision"] == 2, "bare family reference should resolve to the latest ACTIVE revision"
    assert latest["cpu"] == "512", f"expected latest cpu 512, got {latest['cpu']}"

    pinned = ecs.describe_task_definition(taskDefinition=f"{family}:1")["taskDefinition"]
    assert pinned["revision"] == 1, f"expected pinned revision 1, got {pinned['revision']}"
    assert pinned["cpu"] == "256", f"expected pinned cpu 256, got {pinned['cpu']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
