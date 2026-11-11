"""task-protection-ttl-expires-and-clears."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "task-protection-ttl-expires-and-clears"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ecs"]

_ECS_TAGS = [{"key": "sim2real", "value": "true"}]


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_UpdateTaskProtection.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """UpdateTaskProtection(expiresInMinutes=1) sets a protection window that GetTaskProtection
    reports, and the window clears (protectionEnabled -> false) once the TTL elapses."""
    ecs = ctx.client("ecs")
    info = _create_running_service_task(ctx, "sim2real-ecs-ttlprot")
    cluster = info["cluster"]
    task_arn = info["task_arn"]

    # Depending on the account/region's ECS "long ARN format" opt-in setting, the
    # task ARN returned by list/describe-tasks may be a short-form ARN
    # (arn:.../task/<id>) while task-protection APIs always echo the canonical
    # long-form ARN (arn:.../task/<cluster>/<id>) for the very same task. Compare
    # on the trailing task-id segment (the stable identity) rather than requiring
    # byte-for-byte ARN equality.
    task_id = task_arn.rsplit("/", 1)[-1]

    resp = ecs.update_task_protection(
        cluster=cluster, tasks=[task_arn], protectionEnabled=True, expiresInMinutes=1
    )
    assert not resp.get("failures"), f"unexpected failures: {resp.get('failures')}"
    protected = resp["protectedTasks"]
    assert len(protected) == 1, f"expected exactly 1 protectedTasks entry, got {len(protected)}"
    assert protected[0]["taskArn"].rsplit("/", 1)[-1] == task_id, (
        f"expected protected task id {task_id!r}, got {protected[0]['taskArn']!r}"
    )
    assert protected[0]["protectionEnabled"] is True, (
        f"expected protectionEnabled True on UpdateTaskProtection response, got {protected[0]['protectionEnabled']!r}"
    )
    expiration = protected[0]["expirationDate"]
    now = datetime.now(timezone.utc)
    delta_s = (expiration - now).total_seconds()
    assert 15 <= delta_s <= 110, f"expected ~60s TTL window, got {delta_s}s"

    got = ecs.get_task_protection(cluster=cluster, tasks=[task_arn])
    got_protected = got["protectedTasks"][0]
    assert got_protected["taskArn"].rsplit("/", 1)[-1] == task_id, (
        f"expected GetTaskProtection to report task id {task_id!r}, got {got_protected['taskArn']!r}"
    )
    assert got_protected["protectionEnabled"] is True, (
        f"expected GetTaskProtection to report protectionEnabled True right after enabling, "
        f"got {got_protected['protectionEnabled']!r}"
    )

    def _probe():
        r = ecs.get_task_protection(cluster=cluster, tasks=[task_arn])
        return r["protectedTasks"][0]

    cleared = _poll_until(
        _probe, lambda p: p["protectionEnabled"] is False, timeout_s=150.0, interval_s=5.0
    )
    assert cleared["protectionEnabled"] is False, (
        f"expected protectionEnabled to auto-clear to False once the 1-minute TTL elapsed, "
        f"got {cleared['protectionEnabled']!r}"
    )
    assert cleared["taskArn"].rsplit("/", 1)[-1] == task_id, (
        f"expected the cleared GetTaskProtection entry to still be for task id {task_id!r}, "
        f"got {cleared['taskArn']!r}"
    )


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
    ecs.create_cluster(clusterName=cluster_name, tags=_ECS_TAGS)

    def _cleanup_cluster():
        # DeleteCluster is refused until the service's tasks have drained; retry only that.
        deadline = time.monotonic() + 120
        while True:
            try:
                ecs.delete_cluster(cluster=cluster_name)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ClusterNotFoundException":
                    return
                if code not in (
                    "ClusterContainsServicesException", "ClusterContainsTasksException",
                    "ClusterContainsContainerInstancesException", "UpdateInProgressException",
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
        tags=_ECS_TAGS,
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
        tags=_ECS_TAGS,
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
