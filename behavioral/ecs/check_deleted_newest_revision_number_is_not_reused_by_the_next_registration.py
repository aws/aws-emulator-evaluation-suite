"""deleted-newest-revision-number-is-not-reused-by-the-next-registration."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleted-newest-revision-number-is-not-reused-by-the-next-registration"
GROUP = "state"
SERVICES = ["ecs"]
#: Bounded convergence for a deleted revision to leave INACTIVE.
POLL_BUDGET_S = 40.0
#: The container-image prerequisite (a public image name; no container is ever started).
CONTAINER_IMAGE = "public.ecr.aws/amazonlinux/amazonlinux:2023"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deregistering and deleting a family's newest revision 2 does not free its number: the next
    registration is revision 3 and the bare family resolves to it, while revision 1 stays ACTIVE
    and revision 2 reads DELETE_IN_PROGRESS or is refused."""
    _start_budget(ctx)
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-tdn-")

    def _new(memory):
        reg = _register(ecs, family, memory)
        ctx.on_cleanup(lambda a=reg["taskDefinitionArn"]: _cleanup_task_def(ecs, a))
        return reg

    one, two = _new(128), _new(192)
    assert (one["revision"], two["revision"]) == (1, 2), (
        f"expected revisions (1, 2) on a fresh family, got {(one['revision'], two['revision'])!r}"
    )
    ecs.deregister_task_definition(taskDefinition=two["taskDefinitionArn"])
    resp = ecs.delete_task_definitions(taskDefinitions=[two["taskDefinitionArn"]])
    assert not resp.get("failures"), f"deleting the INACTIVE revision 2 reported failures {resp.get('failures')!r}"

    deadline = time.monotonic() + _bounded(POLL_BUDGET_S)
    while True:
        try:
            status = ecs.describe_task_definition(taskDefinition=two["taskDefinitionArn"])["taskDefinition"]["status"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            http = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            got = (err.get("Code"), err.get("Message"))
            assert got == ("ClientException", "Unable to describe task definition."), (
                f"DescribeTaskDefinition on the deleted revision: expected ClientException 'Unable to describe "
                f"task definition.', got {got!r}"
            )
            assert isinstance(http, int) and 400 <= http < 500, f"expected HTTP 4xx, got {http!r}"
            break
        if status == "DELETE_IN_PROGRESS":
            break
        assert status == "INACTIVE", f"a deleted revision should leave INACTIVE, got {status!r}"
        if time.monotonic() > deadline:
            raise AssertionError(f"revision 2 still reads {status!r} {POLL_BUDGET_S:.0f}s after DeleteTaskDefinitions")
        time.sleep(2.0)

    three = _new(256)
    assert three["revision"] == 3, f"the registration after deleting revision 2 must be revision 3, got {three['revision']!r}"
    assert three["taskDefinitionArn"].endswith(f"/{family}:3"), "the new revision's ARN must end in <family>:3"
    bare = ecs.describe_task_definition(taskDefinition=family)["taskDefinition"]
    got = (bare["revision"], bare["containerDefinitions"][0].get("memory"))
    assert got == (3, 256), f"bare family (revision, memory): expected (3, 256), got {got!r}"
    first = ecs.describe_task_definition(taskDefinition=f"{family}:1")["taskDefinition"]
    assert (first["status"], first["containerDefinitions"][0].get("memory")) == ("ACTIVE", 128), (
        f"revision 1 (status, memory): expected ('ACTIVE', 128), got "
        f"{(first['status'], first['containerDefinitions'][0].get('memory'))!r}"
    )
    active = sorted(a for page in ecs.get_paginator("list_task_definitions").paginate(familyPrefix=family, status="ACTIVE")
                    for a in page.get("taskDefinitionArns", []))
    assert active == sorted([one["taskDefinitionArn"], three["taskDefinitionArn"]]), (
        f"ListTaskDefinitions ACTIVE: expected revisions 1 and 3, got {[a.rsplit(':', 1)[-1] for a in active]!r}"
    )


#: The runner's deadline for this check (monotonic clock), set as run() starts.
_RUN_END: dict = {}


def _bounded(timeout_s: float) -> float:
    """``timeout_s`` cut to the time the runner leaves this check, so a wait fails with its own
    last observation rather than the runner's timeout."""
    end = _RUN_END.get("t")
    return timeout_s if end is None else max(1.0, min(timeout_s, end - time.monotonic() - 3.0))


def _start_budget(ctx) -> None:
    left = ctx.time_left()
    _RUN_END["t"] = None if left is None else time.monotonic() + left



def _register(ecs, family: str, memory: int) -> dict:
    """An EC2-compatible bridge-mode revision; the image is only named, never pulled."""
    return ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["EC2"],
        networkMode="bridge",
        containerDefinitions=[
            {"name": "main", "image": CONTAINER_IMAGE, "memory": memory, "command": ["sleep", "60"], "essential": True}
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
