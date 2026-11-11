"""op-contract-stop-task."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "op-contract-stop-task"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopTask on a real running Fargate task flips desiredStatus to STOPPED, echoes the
    supplied reason into stoppedReason, and the task eventually reaches lastStatus STOPPED
    with stopCode UserInitiated; ClusterNotFoundException for a cluster that doesn't exist."""
    ecs = ctx.client("ecs")
    net_cfg = _fargate_network_config(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-stoptask-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    family = ctx.unique_name("sim2real-ecs-stoptask-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        cpu="256",
        memory="512",
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        containerDefinitions=[{"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36",
                                "essential": True, "command": ["sleep", "120"]}],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    run_resp = ecs.run_task(
        cluster=cluster_name, taskDefinition=td_arn, launchType="FARGATE", count=1,
        networkConfiguration={"awsvpcConfiguration": net_cfg},
    )
    assert not run_resp.get("failures"), run_resp.get("failures")
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=cluster_name, task=task_arn, reason="test-cleanup"))

    status = _wait_for_status(ctx, cluster_name, task_arn, {"RUNNING", "STOPPED"}, timeout_s=180)
    if status != "RUNNING":
        raise AssertionError(f"task reached {status} before RUNNING could be observed")

    stop_reason = "sim2real-behavioral-stop-reason"
    stopped_task = ecs.stop_task(cluster=cluster_name, task=task_arn, reason=stop_reason)["task"]
    assert stopped_task["desiredStatus"] == "STOPPED", stopped_task["desiredStatus"]

    final_status = _wait_for_status(ctx, cluster_name, task_arn, {"STOPPED"}, timeout_s=90)
    assert final_status == "STOPPED", final_status

    described = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])["tasks"][0]
    assert described["stoppedReason"] == stop_reason, described["stoppedReason"]
    assert described["stopCode"] == "UserInitiated", described["stopCode"]

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_cluster = ctx.unique_name("sim2real-nonexistent-cluster-")
    bogus_task_arn = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:task/{bogus_cluster}/"
        "00000000000000000000000000000000"
    )
    code, message = _error(lambda: ecs.stop_task(cluster=bogus_cluster, task=bogus_task_arn))
    assert code == "ClusterNotFoundException", code
    assert message == "Cluster not found.", message


# ===== helpers =====
def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, because an emulator accepting input real AWS refuses must fail loudly rather than
    read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _fargate_network_config(ctx):
    """The awsvpcConfiguration for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return {
        "subnets": [net.subnet_ids[0]],
        "securityGroups": [net.security_group_id],
        "assignPublicIp": "ENABLED",
    }


def _wait_for_status(ctx, cluster: str, task_arn: str, target: set[str], timeout_s: float) -> str:
    ecs = ctx.client("ecs")
    last = ""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        # DescribeTasks is eventually consistent right after RunTask/StopTask — the
        # task ARN can be briefly absent, so tolerate an empty list instead of
        # indexing [0].
        tasks = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"]
        if tasks:
            last = tasks[0]["lastStatus"]
        if last in target:
            return last
        time.sleep(3)
    raise AssertionError(f"task did not reach {target} within {timeout_s}s (last={last!r})")


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
                if exc.response["Error"]["Code"] not in ("ServiceNotFoundException", "ServiceNotActiveException"):
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
