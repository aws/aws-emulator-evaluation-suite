"""op-contract-deleteTaskDefinitions."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deleteTaskDefinitions"
GROUP = "error-semantics"
SERVICES = ["ecs"]

_ACTIVE_REASON = (
    "The specified task definition is still in ACTIVE status. Please deregister the target and try again."
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTaskDefinitions permanently deletes a deregistered revision, rejects an ACTIVE
    one via failures[] with a reason naming the ACTIVE-status block and the deregister remedy,
    and accepts the identical call once that same revision is deregistered."""
    ecs = ctx.client("ecs")

    family_del = ctx.unique_name("sim2real-behav-td-del-")
    reg = ecs.register_task_definition(
        family=family_del,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "cpu": 128,
                "memory": 128,
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    arn_del = reg["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _cleanup_taskdef(ecs, arn_del))
    ecs.deregister_task_definition(taskDefinition=arn_del)

    resp = ecs.delete_task_definitions(taskDefinitions=[arn_del])
    assert resp.get("failures", []) == [], (
        f"expected no failures deleting an INACTIVE task definition, got {resp.get('failures')!r}"
    )
    assert len(resp["taskDefinitions"]) == 1, (
        f"expected exactly one taskDefinitions entry, got {resp['taskDefinitions']!r}"
    )
    assert resp["taskDefinitions"][0]["status"] == "DELETE_IN_PROGRESS", (
        f"expected DELETE_IN_PROGRESS, got {resp['taskDefinitions'][0]['status']!r}"
    )
    assert resp["taskDefinitions"][0]["taskDefinitionArn"] == arn_del, (
        f"expected {arn_del}, got {resp['taskDefinitions'][0]['taskDefinitionArn']!r}"
    )

    _assert_delete_in_progress(ecs, arn_del)

    family_active = ctx.unique_name("sim2real-behav-td-active-")
    reg2 = ecs.register_task_definition(
        family=family_active,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "cpu": 128,
                "memory": 128,
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    arn_active = reg2["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _cleanup_taskdef(ecs, arn_active))

    assert reg2["taskDefinition"]["status"] == "ACTIVE", (
        f"positive control: expected a freshly registered revision ACTIVE, "
        f"got {reg2['taskDefinition']['status']!r}"
    )

    resp2 = ecs.delete_task_definitions(taskDefinitions=[arn_active])
    assert resp2["taskDefinitions"] == [], (
        f"expected an ACTIVE task definition to not be deleted, got taskDefinitions={resp2['taskDefinitions']!r}"
    )
    assert len(resp2["failures"]) == 1, (
        f"expected exactly one failure entry for the ACTIVE task definition, got {resp2['failures']!r}"
    )
    assert resp2["failures"][0]["arn"] == arn_active, (
        f"expected failure arn {arn_active}, got {resp2['failures'][0]['arn']!r}"
    )
    reason = resp2["failures"][0].get("reason", "")
    assert reason == _ACTIVE_REASON, (
        f"expected the failure reason to name the ACTIVE-status block and the deregister remedy, "
        f"got {reason!r}"
    )

    still_active = ecs.describe_task_definition(taskDefinition=arn_active)["taskDefinition"]
    assert still_active["status"] == "ACTIVE", (
        f"independent read expected the rejected delete to leave status ACTIVE, got {still_active['status']!r}"
    )

    ecs.deregister_task_definition(taskDefinition=arn_active)
    now_inactive = ecs.describe_task_definition(taskDefinition=arn_active)["taskDefinition"]
    assert now_inactive["status"] == "INACTIVE", (
        f"expected deregister to move status to INACTIVE, got {now_inactive['status']!r}"
    )

    resp3 = ecs.delete_task_definitions(taskDefinitions=[arn_active])
    assert resp3.get("failures", []) == [], (
        f"expected the identical delete call to succeed once INACTIVE, got failures={resp3.get('failures')!r}"
    )
    assert len(resp3["taskDefinitions"]) == 1, (
        f"expected exactly one taskDefinitions entry, got {resp3['taskDefinitions']!r}"
    )
    assert resp3["taskDefinitions"][0]["status"] == "DELETE_IN_PROGRESS", (
        f"expected DELETE_IN_PROGRESS, got {resp3['taskDefinitions'][0]['status']!r}"
    )

    _assert_delete_in_progress(ecs, arn_active)


def _cleanup_taskdef(ecs, arn: str) -> None:
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


def _assert_delete_in_progress(ecs, arn: str) -> None:
    """Independent read: DescribeTaskDefinition reports the revision DELETE_IN_PROGRESS, the
    state it holds for minutes after an accepted delete."""
    status = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]["status"]
    assert status == "DELETE_IN_PROGRESS", (
        f"expected the independent read to show the revision being deleted, got {status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
