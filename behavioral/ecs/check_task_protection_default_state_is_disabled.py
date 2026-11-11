"""task-protection-default-state-is-disabled."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "task-protection-default-state-is-disabled"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTaskProtection on a task that never had UpdateTaskProtection called on it reports
    protectionEnabled=false and no expirationDate."""
    ecs = ctx.client("ecs")
    info = _create_running_service_task(ctx, "sim2real-ecs-defprot")
    cluster = info["cluster"]
    task_arn = info["task_arn"]

    resp = ecs.get_task_protection(cluster=cluster, tasks=[task_arn])
    assert not resp.get("failures"), f"unexpected failures: {resp.get('failures')}"
    protected = resp["protectedTasks"]
    assert len(protected) == 1, f"expected exactly 1 protectedTasks entry, got {len(protected)}: {protected}"
    entry = protected[0]
    assert entry["taskArn"] == task_arn, f"expected taskArn {task_arn!r}, got {entry['taskArn']!r}"
    assert entry["protectionEnabled"] is False, (
        f"expected protectionEnabled False for a task that never had UpdateTaskProtection called, "
        f"got {entry['protectionEnabled']!r}"
    )
    assert entry.get("expirationDate") is None, f"expected no expiration, got {entry.get('expirationDate')}"


# ===== helpers =====


def _default_networking(ctx):

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region for Fargate networking")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return subnet_id, sgs[0]["GroupId"]


def _poll_until(probe, predicate, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_running_service_task(ctx, name_prefix):
    """Create a cluster + Fargate service with 1 desired count and wait for a RUNNING task."""
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _default_networking(ctx)

    cluster_name = ctx.unique_name(f"{name_prefix}-cl-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])

    def _cleanup_cluster():
        # DeleteCluster is refused until the force-deleted service's tasks have stopped.
        deadline = time.monotonic() + 300
        while True:
            try:
                ecs.delete_cluster(cluster=cluster_name)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ClusterNotFoundException":
                    return
                if code not in (
                    "ClusterContainsServicesException",
                    "ClusterContainsTasksException",
                    "UpdateInProgressException",
                ) or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    family = ctx.unique_name(f"{name_prefix}-td-")
    ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sleep", "1800"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )

    def _cleanup_taskdef():
        _retire_task_definition(ecs, f"{family}:1")

    service_name = ctx.unique_name(f"{name_prefix}-svc-")
    ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=family,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [subnet_id],
                "securityGroups": [sg_id],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=[{"key": "sim2real", "value": "true"}],
    )

    def _cleanup_service():
        try:
            ecs.delete_service(cluster=cluster_name, service=service_name, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ClusterNotFoundException",
                "ServiceNotFoundException",
            ):
                raise
        for _ in range(24):
            d = ecs.describe_clusters(clusters=[cluster_name])["clusters"]
            if not d or d[0].get("activeServicesCount", 0) == 0:
                return
            time.sleep(5)

    ctx.on_cleanup(_cleanup_cluster)
    ctx.on_cleanup(_cleanup_taskdef)
    ctx.on_cleanup(_cleanup_service)

    def _find_running_task():
        arns = ecs.list_tasks(cluster=cluster_name, serviceName=service_name).get("taskArns", [])
        if not arns:
            return None
        tasks = ecs.describe_tasks(cluster=cluster_name, tasks=arns).get("tasks", [])
        for t in tasks:
            if t.get("lastStatus") == "RUNNING":
                return t
        return None

    task = _poll_until(_find_running_task, lambda t: t is not None, timeout_s=240.0, interval_s=5.0)
    return {
        "cluster": cluster_name,
        "service": service_name,
        "family": family,
        "task_arn": task["taskArn"],
    }


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
