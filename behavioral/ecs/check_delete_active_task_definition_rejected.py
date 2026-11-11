"""delete-active-task-definition-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-active-task-definition-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]

_ACTIVE_REASON = (
    "The specified task definition is still in ACTIVE status. Please deregister the target and try again."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTaskDefinitions on an ACTIVE revision reports it in failures with the exact reason,
    deletes nothing and leaves it ACTIVE; once deregistered, the same call returns it as
    DELETE_IN_PROGRESS with no failures."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-tdactive-")
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
    )["taskDefinition"]
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _cleanup_task_def(ecs, arn))

    assert td["status"] == "ACTIVE"
    resp = ecs.delete_task_definitions(taskDefinitions=[arn])
    failures = resp.get("failures", [])
    assert failures == [{"arn": arn, "reason": _ACTIVE_REASON}], (
        f"expected delete_task_definitions to report one failure entry for an ACTIVE task "
        f"definition, got failures={failures!r}"
    )
    deleted_arns = {t["taskDefinitionArn"] for t in resp.get("taskDefinitions", [])}
    assert arn not in deleted_arns, f"ACTIVE task definition {arn} was unexpectedly deleted"

    # confirm it is unaffected and still ACTIVE
    described = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    assert described["status"] == "ACTIVE"

    # restore: deregister so the revision becomes INACTIVE, then retry the identical
    # delete call. Without this leg the check above cannot tell "rejects only ACTIVE
    # revisions" apart from "rejects every DeleteTaskDefinitions call".
    ecs.deregister_task_definition(taskDefinition=arn)
    resp2 = ecs.delete_task_definitions(taskDefinitions=[arn])
    assert not resp2.get("failures"), (
        f"expected no failures deleting an INACTIVE task definition, got {resp2.get('failures')!r}"
    )
    redeleted = {t["taskDefinitionArn"]: t["status"] for t in resp2.get("taskDefinitions", [])}
    assert arn in redeleted, f"expected {arn} in deleted taskDefinitions, got {resp2!r}"
    # the delete call's own response carries the documented resting state of an accepted delete
    assert redeleted[arn] == "DELETE_IN_PROGRESS", f"expected DELETE_IN_PROGRESS, got {redeleted[arn]!r}"

    _assert_delete_in_progress(ecs, arn)


def _assert_delete_in_progress(ecs, arn: str) -> None:
    """Independent read: DescribeTaskDefinition reports the revision DELETE_IN_PROGRESS, the
    state it holds for minutes after an accepted delete."""
    status = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]["status"]
    assert status == "DELETE_IN_PROGRESS", (
        f"expected the independent read to show the revision being deleted, got {status!r}"
    )


def _cleanup_task_def(ecs, arn: str) -> None:
    try:
        ecs.deregister_task_definition(taskDefinition=arn)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted"))
        ):
            raise
    ecs.delete_task_definitions(taskDefinitions=[arn])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
