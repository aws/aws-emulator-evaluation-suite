"""delete-primary-task-set-without-force-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-primary-task-set-without-force-rejected"
GROUP = "concurrency"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTaskSet without force=True is rejected for the PRIMARY task set, which stays PRIMARY;
    it succeeds for a non-primary task set, and for the same one again once demoted."""
    ecs = ctx.client("ecs")
    subnet_id, _vpc_id = _default_subnet(ctx)

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-behav-td-")
    task_def_arn = _register_fargate_task_def(ctx, family)

    service_name = ctx.unique_name("sim2real-behav-svc-")
    service_arn = ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        desiredCount=0,
        deploymentController={"type": "EXTERNAL"},
    )["service"]["serviceArn"]
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True))

    net_cfg = {"awsvpcConfiguration": {"subnets": [subnet_id], "assignPublicIp": "ENABLED"}}

    def _create_task_set() -> dict[str, Any]:
        created = ecs.create_task_set(
            cluster=cluster_arn, service=service_arn, taskDefinition=task_def_arn,
            launchType="FARGATE", networkConfiguration=net_cfg,
        )["taskSet"]
        ctx.on_cleanup(
            lambda: ecs.delete_task_set(
                cluster=cluster_arn, service=service_arn, taskSet=created["id"], force=True
            )
        )
        return created

    def _describe(ts_id: str) -> list[dict[str, Any]]:
        return ecs.describe_task_sets(
            cluster=cluster_arn, service=service_arn, taskSets=[ts_id]
        )["taskSets"]

    ts_a = _create_task_set()
    a_id = ts_a["id"]
    ts_b = _create_task_set()
    b_id = ts_b["id"]

    # Positive control: with no task set PRIMARY yet, a delete without force succeeds.
    described_b = _describe(b_id)[0]
    assert described_b["status"] != "PRIMARY", f"control task set must not start PRIMARY, got {described_b['status']!r}"
    ecs.delete_task_set(cluster=cluster_arn, service=service_arn, taskSet=b_id)
    gone_b = _poll_until(
        lambda: _describe(b_id), lambda ts: not ts, timeout_s=60.0, interval_s=3.0,
    )
    assert gone_b == [], "positive control: deleting a non-PRIMARY task set without force must succeed"

    ecs.update_service_primary_task_set(cluster=cluster_arn, service=service_arn, primaryTaskSet=a_id)
    described_a = _poll_until(
        lambda: _describe(a_id)[0], lambda s: s["status"] == "PRIMARY", timeout_s=20.0, interval_s=1.0,
    )
    assert described_a["status"] == "PRIMARY"

    code, message = _error(lambda: ecs.delete_task_set(cluster=cluster_arn, service=service_arn, taskSet=a_id))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert message == 'Primary TaskSet cannot be deleted', f"expected the exact PRIMARY-task-set message, got {message!r}"

    # The task set must still exist and remain PRIMARY after the rejected delete.
    still_there = _describe(a_id)
    assert len(still_there) == 1 and still_there[0]["status"] == "PRIMARY"

    # Restore: promoting a third task set demotes A off PRIMARY, lifting the restriction.
    ts_c = _create_task_set()
    c_id = ts_c["id"]
    ecs.update_service_primary_task_set(cluster=cluster_arn, service=service_arn, primaryTaskSet=c_id)
    demoted_a = _poll_until(
        lambda: _describe(a_id)[0], lambda s: s["status"] != "PRIMARY", timeout_s=20.0, interval_s=1.0,
    )
    assert demoted_a["status"] != "PRIMARY", f"A should be demoted once C is PRIMARY, got {demoted_a['status']!r}"

    # The identical call — same cluster, service, task set, still no force — now succeeds.
    ecs.delete_task_set(cluster=cluster_arn, service=service_arn, taskSet=a_id)
    gone_a = _poll_until(
        lambda: _describe(a_id), lambda ts: not ts, timeout_s=60.0, interval_s=3.0,
    )
    assert gone_a == [], "the identical delete call must succeed once the task set is no longer PRIMARY"



def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error code and message. An unexpected success raises."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if isinstance(resp, dict):
            return resp["Error"]["Code"], resp["Error"].get("Message", "")
        raise
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _default_subnet(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError("no shared network VPC subnet available for FARGATE networking")
    return subnets[0]["SubnetId"], subnets[0]["VpcId"]


def _register_fargate_task_def(ctx, family: str) -> str:
    ecs = ctx.client("ecs")
    container: dict[str, Any] = {
        "name": "app",
        "image": "public.ecr.aws/docker/library/alpine:3.20",
        "essential": True,
    }
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[container],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn



def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services, tasks or container instances remain, and a task's
    ENI stays in the shared network until the task has stopped, which keeps the network from
    being deleted.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s

    def arns(op, key, **kw):
        return [a for page in ecs.get_paginator(op).paginate(cluster=cluster, **kw) for a in page.get(key, [])]

    try:
        services = arns("list_services", "serviceArns")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ClusterNotFoundException":
            return
        raise
    for service in services:
        for call in (
            lambda s=service: ecs.update_service(cluster=cluster, service=s, desiredCount=0),
            lambda s=service: ecs.delete_service(cluster=cluster, service=s, force=True),
        ):
            try:
                call()
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "ClusterNotFoundException",
                    "ServiceNotFoundException",
                    "ServiceNotActiveException",
                ):
                    raise
    while True:
        for task in arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            try:
                ecs.stop_task(cluster=cluster, task=task, reason="sim2real teardown")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                    raise
        stopping = arns("list_tasks", "taskArns", desiredStatus="STOPPED")
        live = []
        for i in range(0, len(stopping), 100):
            live += [t for t in ecs.describe_tasks(cluster=cluster, tasks=stopping[i:i + 100])["tasks"]
                     if t.get("lastStatus") != "STOPPED"]
        if not live and not arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{len(live)} task(s) in {cluster} still not STOPPED after {timeout_s:.0f}s")
        time.sleep(interval_s)
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code == "ClusterContainsContainerInstancesException":
                for instance in arns("list_container_instances", "containerInstanceArns"):
                    try:
                        ecs.deregister_container_instance(cluster=cluster, containerInstance=instance, force=True)
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                            raise
            elif code not in (
                "ClusterContainsTasksException",
                "ClusterContainsServicesException",
                "UpdateInProgressException",
                "ResourceInUseException",
            ):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
