"""create-task-set-default-controller-rejected-deployment-unchanged."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-task-set-default-controller-rejected-deployment-unchanged"
GROUP = "overly-permissive"
SERVICES = ["ecs"]

_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "amazonlinux:2",
        "cpu": 10,
        "memory": 64,
        "essential": True,
    }
]

_SCALE = {"value": 100.0, "unit": "PERCENT"}

_REFUSED = (
    "InvalidParameterException",
    "Amazon ECS only supports task set management on services configured to use "
    "external deployment controllers.",
)


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _deployment_snapshot(deployments):
    return [
        {
            "id": d["id"],
            "status": d["status"],
            "taskDefinition": d["taskDefinition"],
            "desiredCount": d["desiredCount"],
            "pendingCount": d["pendingCount"],
            "runningCount": d["runningCount"],
            "rolloutState": d["rolloutState"],
        }
        for d in deployments
    ]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTaskSet on a default-controller service is refused InvalidParameterException and
    leaves its deployments and taskSets unchanged, while the identical call against an
    EXTERNAL-controller service creates a task set whose fields read back as requested."""
    ecs = ctx.client("ecs")
    cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))["cluster"]
    ctx.on_cleanup(lambda c=cluster: ecs.delete_cluster(cluster=c["clusterName"]))
    cluster_name = cluster["clusterName"]

    task_def = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-"),
        requiresCompatibilities=["EC2"],
        networkMode="bridge",
        containerDefinitions=_CONTAINER_DEFS,
    )["taskDefinition"]
    ctx.on_cleanup(lambda a=task_def["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=task_def["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))
    td_arn = task_def["taskDefinitionArn"]

    default_svc_name = ctx.unique_name("sim2real-behav-ecs-svc-default-")
    ecs.create_service(
        cluster=cluster_name,
        serviceName=default_svc_name,
        taskDefinition=td_arn,
        desiredCount=0,
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=default_svc_name, force=True))

    def _describe_default():
        return ecs.describe_services(cluster=cluster_name, services=[default_svc_name])["services"][0]

    # Let the service's own deployment reach a terminal rollout state before the
    # refused call, so the before/after comparison below is between two stable reads.
    before = _poll_until(_describe_default, lambda s: s["deployments"][0]["rolloutState"] == "COMPLETED")
    before_task_sets = before.get("taskSets", [])
    before_deployments = _deployment_snapshot(before["deployments"])

    expect_error(
        lambda: ecs.create_task_set(
            cluster=cluster_name,
            service=default_svc_name,
            taskDefinition=td_arn,
            launchType="EC2",
            scale=_SCALE,
        ),
        *_REFUSED,
    )

    after = _describe_default()
    assert after.get("taskSets", []) == before_task_sets == [], (
        f"a task set was created despite the rejection: {after.get('taskSets')}"
    )
    after_deployments = _deployment_snapshot(after["deployments"])
    assert after_deployments == before_deployments, (
        f"the refused CreateTaskSet changed the service's deployments: "
        f"before={before_deployments!r}, after={after_deployments!r}"
    )

    # Positive control: the identical call succeeds against an EXTERNAL-controller
    # service in the same cluster, using the same task definition.
    ext_svc_name = ctx.unique_name("sim2real-behav-ecs-svc-ext-")
    ecs.create_service(
        cluster=cluster_name,
        serviceName=ext_svc_name,
        desiredCount=0,
        deploymentController={"type": "EXTERNAL"},
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=ext_svc_name, force=True))

    created = ecs.create_task_set(
        cluster=cluster_name,
        service=ext_svc_name,
        taskDefinition=td_arn,
        launchType="EC2",
        scale=_SCALE,
    )["taskSet"]
    ts_id = created["id"]
    ctx.on_cleanup(
        lambda: ecs.delete_task_set(cluster=cluster_name, service=ext_svc_name, taskSet=ts_id, force=True)
    )
    assert created["taskDefinition"] == td_arn, (
        f"expected created task set taskDefinition {td_arn!r}, got {created['taskDefinition']!r}"
    )
    assert created["launchType"] == "EC2", f"expected created task set launchType 'EC2', got {created['launchType']!r}"
    assert created["scale"] == _SCALE, f"expected created task set scale {_SCALE!r}, got {created['scale']!r}"

    read_back = ecs.describe_task_sets(cluster=cluster_name, service=ext_svc_name, taskSets=[ts_id])[
        "taskSets"
    ]
    assert len(read_back) == 1, f"expected exactly one task set read back for {ts_id!r}, got {read_back!r}"
    ts = read_back[0]
    assert ts["taskDefinition"] == td_arn, (
        f"expected read-back taskDefinition {td_arn!r}, got {ts['taskDefinition']!r}"
    )
    assert ts["launchType"] == "EC2", f"expected read-back launchType 'EC2', got {ts['launchType']!r}"
    assert ts["scale"] == _SCALE, f"expected read-back scale {_SCALE!r}, got {ts['scale']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
