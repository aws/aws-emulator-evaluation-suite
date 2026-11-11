"""task-definition-family-revision-increment."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "task-definition-family-revision-increment"
GROUP = "state"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeated RegisterTaskDefinition calls on the same family increment revision
    sequentially, the returned ARN encodes the revision number, and an independent
    ListTaskDefinitions read reflects the same family in the same sequential order."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-tdrev-")
    arns: list[str] = []
    ctx.on_cleanup(lambda: _cleanup_family(ecs, arns))

    revisions = []
    for _ in range(3):
        td = ecs.register_task_definition(
            family=family,
            requiresCompatibilities=["FARGATE"],
            networkMode="awsvpc",
            cpu="256",
            memory="512",
            containerDefinitions=[
                {
                    "name": "main",
                    "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                    "command": ["sleep", "60"],
                    "essential": True,
                }
            ],
            tags=[{"key": "sim2real", "value": "true"}],
        )["taskDefinition"]
        arns.append(td["taskDefinitionArn"])
        revisions.append(td["revision"])

    assert revisions == [1, 2, 3], f"expected sequential revisions 1,2,3 got {revisions}"
    for i, arn in enumerate(arns, start=1):
        assert arn.endswith(f":{i}"), f"ARN {arn} does not end with revision {i}"

    listed = ecs.list_task_definitions(familyPrefix=family, sort="ASC")["taskDefinitionArns"]
    assert listed == arns, (
        f"independent ListTaskDefinitions read does not reflect the same sequential "
        f"registration order: expected {arns} got {listed}"
    )


def _cleanup_family(ecs, arns: list[str]) -> None:
    for a in arns:
        try:
            ecs.deregister_task_definition(taskDefinition=a)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted"))
            ):
                raise
    if arns:
        ecs.delete_task_definitions(taskDefinitions=arns[:10])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
