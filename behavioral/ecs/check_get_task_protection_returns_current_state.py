"""get-task-protection-returns-current-state."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-task-protection-returns-current-state"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTaskProtection reflects the protection state most recently set by UpdateTaskProtection
    for a RUNNING task that belongs to a service (enable, verify, disable, verify)."""
    ecs = ctx.client("ecs")
    net = _default_network(ctx)

    cluster_name = ctx.unique_name("sim2real-behav-prot-cluster-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_retrying(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-behav-prot-task-")
    task_def = _register_sleep_task_def(ctx, family)
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def))

    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": net["subnet_ids"],
            "securityGroups": [net["security_group_id"]] if net["security_group_id"] else [],
            "assignPublicIp": "ENABLED",
        }
    }

    service_name = ctx.unique_name("sim2real-behav-prot-svc-")
    ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        taskDefinition=task_def,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: ecs.delete_service(cluster=cluster_arn, service=service_name, force=True)
        )
    )

    task_arn = _poll_until(
        lambda: (ecs.list_tasks(cluster=cluster_arn, serviceName=service_name)["taskArns"] or [None])[0],
        lambda arn: arn is not None,
        timeout_s=180,
        interval_s=5,
    )
    _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]["lastStatus"],
        lambda status: status == "RUNNING",
        timeout_s=180,
        interval_s=5,
    )

    enabled = ecs.update_task_protection(
        cluster=cluster_arn, tasks=[task_arn], protectionEnabled=True, expiresInMinutes=5
    )
    assert not enabled["failures"], enabled["failures"]
    assert enabled["protectedTasks"][0]["protectionEnabled"] is True

    got = ecs.get_task_protection(cluster=cluster_arn, tasks=[task_arn])
    assert not got["failures"], got["failures"]
    got_protected = got["protectedTasks"][0]
    # Compare by task ID, not byte-identical ARN: ECS may echo the taskArn in a different ARN
    # "shape" (with/without the cluster-name path segment) depending on the account's ARN-format
    # settings, while still identifying the same task.
    assert _task_id(got_protected["taskArn"]) == _task_id(task_arn), (
        f"GetTaskProtection named task id {_task_id(got_protected['taskArn'])!r}, "
        f"expected {_task_id(task_arn)!r}"
    )
    assert got_protected["protectionEnabled"] is True
    assert got_protected.get("expirationDate") is not None

    disabled = ecs.update_task_protection(cluster=cluster_arn, tasks=[task_arn], protectionEnabled=False)
    assert disabled["protectedTasks"][0]["protectionEnabled"] is False

    got_after = ecs.get_task_protection(cluster=cluster_arn, tasks=[task_arn])
    assert got_after["protectedTasks"][0]["protectionEnabled"] is False


# ===== helpers =====
def _ignore_client_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _task_id(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


def _delete_cluster_retrying(ecs, cluster_arn: str, timeout_s: float = 60.0) -> None:
    """DeleteCluster right after a force DeleteService can race the service's tasks actually
    stopping (ENI detach lags the task's own STOPPED status), returning
    ClusterContains{Tasks,Services}Exception on an account that is otherwise draining correctly.
    Retry instead of letting that race silently leak the cluster (and any still-stopping Fargate
    task inside it)."""
    deadline = time.monotonic() + timeout_s
    retryable = {
        "ClusterContainsTasksException",
        "ClusterContainsServicesException",
        "ClusterContainsContainerInstancesException",
        "ClusterContainsCapacityProviderException",
        "UpdateInProgressException",
    }
    while True:
        try:
            _drain_and_delete_ecs_cluster(ecs, cluster_arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in retryable and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return {
        "vpc_id": vpc_id,
        "subnet_ids": [s["SubnetId"] for s in subnets[:2]],
        "security_group_id": sg_id,
    }


def _register_sleep_task_def(ctx, family):
    ecs = ctx.client("ecs")
    return ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "command": ["sleep", "1800"],
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]["taskDefinitionArn"]



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
