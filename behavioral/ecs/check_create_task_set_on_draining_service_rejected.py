"""create-task-set-on-draining-service-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-task-set-on-draining-service-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTaskSet succeeds on an ACTIVE EXTERNAL service but is refused once the service is draining."""
    ecs = ctx.client("ecs")
    resource_tags = [{"key": "sim2real-check", "value": CHECK}]
    cluster_name = ctx.unique_name("sim2real-cts-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=resource_tags)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    taskdef_arn = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-cts-taskdef-"),
        networkMode="bridge",
        requiresCompatibilities=["EC2"],
        containerDefinitions=[
            {"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36", "cpu": 64, "memory": 64, "essential": True, "command": ["sleep", "60"]}
        ],
        tags=resource_tags,
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, taskdef_arn))

    service_name = ctx.unique_name("sim2real-cts-svc-")
    ecs.create_service(
        cluster=cluster_name, serviceName=service_name, desiredCount=0, deploymentController={"type": "EXTERNAL"}, tags=resource_tags
    )
    ctx.on_cleanup(lambda: _safe_delete_service(ecs, cluster_name, service_name))

    # positive control: CreateTaskSet succeeds while the service is ACTIVE.
    ts_arn = ecs.create_task_set(
        cluster=cluster_name, service=service_name, taskDefinition=taskdef_arn, launchType="EC2", scale={"value": 100, "unit": "PERCENT"}
    )["taskSet"]["taskSetArn"]
    ts_status = ecs.describe_task_sets(cluster=cluster_name, service=service_name, taskSets=[ts_arn])["taskSets"][0]["status"]
    assert ts_status in ("PRIMARY", "ACTIVE"), f"expected the positive-control task set to be PRIMARY/ACTIVE, got {ts_status}"
    ecs.delete_task_set(cluster=cluster_name, service=service_name, taskSet=ts_arn, force=True)

    # DeleteTaskSet(force=True) is asynchronous -- the task set can linger (e.g. status
    # DRAINING) in the service's `taskSets` list for a while after the call returns. Wait for
    # it to actually clear before treating the service as a clean baseline for the later
    # "no task set was created" assertion; otherwise this pre-existing task set's own
    # still-in-progress removal gets misread as evidence that the rejected CreateTaskSet call
    # below somehow still created one.
    def _positive_control_task_set_gone():
        described = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"]
        task_sets = described[0].get("taskSets", []) if described else []
        return not any(t.get("taskSetArn") == ts_arn for t in task_sets)

    _poll_until(_positive_control_task_set_gone, lambda gone: gone, timeout_s=120, interval_s=5)

    ecs.delete_service(cluster=cluster_name, service=service_name)
    described = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"]
    assert described and described[0]["status"] in ("DRAINING", "INACTIVE"), f"service did not start draining: {described}"

    code, message = _error(
        lambda: ecs.create_task_set(
            cluster=cluster_name, service=service_name, taskDefinition=taskdef_arn, launchType="EC2", scale={"value": 100, "unit": "PERCENT"}
        )
    )
    assert code == "ServiceNotActiveException", f"expected ServiceNotActiveException creating a task set on a draining service, got {code}"
    assert message == "Service was not ACTIVE.", f"unexpected message: {message!r}"

    # Real ECS rejects DescribeTaskSets when no explicit `taskSets` ARNs are given (it does not
    # act as a "list all task sets" call the way the parameter's optionality suggests), so check
    # for the forbidden effect via the service's own `taskSets` field instead.
    remaining_services = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"]
    remaining = remaining_services[0].get("taskSets", []) if remaining_services else []
    assert remaining == [], f"a task set was created despite the service not being active: {remaining}"


# ===== helpers =====

def _poll_until(probe, predicate, timeout_s=120, interval_s=3):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_service(ecs, cluster_name, service_name):
    try:
        ecs.delete_service(cluster=cluster_name, service=service_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
