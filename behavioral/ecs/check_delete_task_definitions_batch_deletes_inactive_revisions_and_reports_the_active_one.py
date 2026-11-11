"""delete-task-definitions-batch-deletes-inactive-revisions-and-reports-the-active-one."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-task-definitions-batch-deletes-inactive-revisions-and-reports-the-active-one"
GROUP = "state"
SERVICES = ["ecs"]
#: The container-image prerequisite (a public image name; no container is ever started).
CONTAINER_IMAGE = "public.ecr.aws/amazonlinux/amazonlinux:2023"
_ACTIVE_REASON = "The specified task definition is still in ACTIVE status. Please deregister the target and try again."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """One DeleteTaskDefinitions over three Fargate revisions, the middle one still ACTIVE, deletes
    the two INACTIVE ones (DELETE_IN_PROGRESS) and reports only the ACTIVE one in failures; that
    revision stays ACTIVE and is what the bare family and the ACTIVE listing resolve to."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-tdb-")

    arns = []
    for _ in range(3):
        reg = _register(ecs, family)
        ctx.on_cleanup(lambda a=reg["taskDefinitionArn"]: _cleanup_task_def(ecs, a))
        arns.append(reg["taskDefinitionArn"])
        assert (reg["revision"], reg["status"]) == (len(arns), "ACTIVE"), (
            f"registration {len(arns)}: expected (revision, status) ({len(arns)}, 'ACTIVE'), got "
            f"{(reg['revision'], reg['status'])!r}"
        )
    first, middle, last = arns
    described = ecs.describe_task_definition(taskDefinition=middle)["taskDefinition"]
    got = (described.get("networkMode"), described.get("cpu"), described.get("memory"),
           described.get("requiresCompatibilities"))
    assert got == ("awsvpc", "256", "512", ["FARGATE"]), (
        f"revision 2 (networkMode, cpu, memory, compatibilities): expected ('awsvpc', '256', '512', ['FARGATE']), got {got!r}"
    )

    for arn in (first, last):
        status = ecs.deregister_task_definition(taskDefinition=arn)["taskDefinition"]["status"]
        assert status == "INACTIVE", f"DeregisterTaskDefinition: expected INACTIVE, got {status!r}"

    resp = ecs.delete_task_definitions(taskDefinitions=[first, middle, last])
    deleted = {t["taskDefinitionArn"]: t["status"] for t in resp.get("taskDefinitions") or []}
    assert deleted == {first: "DELETE_IN_PROGRESS", last: "DELETE_IN_PROGRESS"}, (
        f"DeleteTaskDefinitions taskDefinitions: expected revisions 1 and 3 DELETE_IN_PROGRESS, got "
        f"{ {a.rsplit(':', 1)[-1]: s for a, s in deleted.items()}!r}"
    )
    failures = resp.get("failures") or []
    assert failures == [{"arn": middle, "reason": _ACTIVE_REASON}], (
        f"DeleteTaskDefinitions failures: expected only revision 2 with {_ACTIVE_REASON!r}, got {failures!r}"
    )

    # Independent reads: the reported revision is untouched and is the family's only ACTIVE one.
    status = ecs.describe_task_definition(taskDefinition=middle)["taskDefinition"]["status"]
    assert status == "ACTIVE", f"the revision reported in failures must stay ACTIVE, got {status!r}"
    bare = ecs.describe_task_definition(taskDefinition=family)["taskDefinition"]
    assert (bare["revision"], bare["status"]) == (2, "ACTIVE"), (
        f"the bare family must resolve to revision 2, the only ACTIVE one; got {(bare['revision'], bare['status'])!r}"
    )
    active = [a for page in ecs.get_paginator("list_task_definitions").paginate(familyPrefix=family, status="ACTIVE")
              for a in page.get("taskDefinitionArns", [])]
    assert active == [middle], f"ListTaskDefinitions ACTIVE for the family: expected only revision 2, got {active!r}"


def _register(ecs, family: str) -> dict:
    """A Fargate awsvpc revision; the image is only named, never pulled."""
    return ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {"name": "main", "image": CONTAINER_IMAGE, "command": ["sleep", "60"], "essential": True}
        ],
    )["taskDefinition"]


def _cleanup_task_def(ecs, arn: str) -> None:
    """Deregister and delete the revision; ECS's ClientException (already inactive/deleted) is the
    only tolerated refusal. DeleteTaskDefinitions reports a per-ARN failure instead of raising."""
    try:
        ecs.deregister_task_definition(taskDefinition=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ClientException":
            raise
    try:
        ecs.delete_task_definitions(taskDefinitions=[arn])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ClientException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
