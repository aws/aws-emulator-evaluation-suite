"""ecs-delete-cluster-with-active-service-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecs-delete-cluster-with-active-service-rejected"
GROUP = "deploy"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster is rejected while an ECS service is still active on it, and the cluster
    is left untouched; scaling the service to zero and deleting it first lets the same
    DeleteCluster call succeed (positive control)."""
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-ecs-svccluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: _best_effort_teardown(ctx, cluster_name))

    family = ctx.unique_name("sim2real-ecs-svccluster-td-")
    task_def_arn = _register_fargate_task_def(ctx, family)
    subnets, sg_id = _default_network_config(ctx)

    service_name = ctx.unique_name("sim2real-ecs-svccluster-svc-")
    create_resp = ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=task_def_arn,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets,
                "securityGroups": [sg_id],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=[{"key": "sim2real", "value": "true"}],
    )
    service_arn = create_resp["service"]["serviceArn"]

    svc = _wait_service_steady(ctx, cluster_name, service_arn, timeout_s=300.0)
    assert svc["runningCount"] == 1, f"expected runningCount=1 once steady, got {svc['runningCount']!r}"

    code, message = _error(lambda: ecs.delete_cluster(cluster=cluster_name))
    assert code == "ClusterContainsServicesException", f"unexpected code/result: {code!r}"
    assert message == "The Cluster cannot be deleted while Services are active.", f"unexpected message: {message!r}"

    # Effect absent: the cluster is still ACTIVE with the service still running on it.
    still_there = ecs.describe_clusters(clusters=[cluster_name])["clusters"][0]
    assert still_there["status"] == "ACTIVE", f"expected cluster status=ACTIVE (untouched), got {still_there['status']!r}"
    assert still_there["activeServicesCount"] == 1, (
        f"expected activeServicesCount=1 (rejected delete left the service), got {still_there['activeServicesCount']!r}"
    )

    # Positive control: scaling to zero and deleting the service first lets DeleteCluster succeed.
    ecs.update_service(cluster=cluster_name, service=service_arn, desiredCount=0)
    _poll_until(
        lambda: ecs.describe_services(cluster=cluster_name, services=[service_arn])["services"][0],
        lambda s: s["runningCount"] == 0 and s["pendingCount"] == 0,
        timeout_s=180.0,
        interval_s=5.0,
    )
    ecs.delete_service(cluster=cluster_name, service=service_arn)
    _poll_until(
        lambda: ecs.describe_services(cluster=cluster_name, services=[service_arn])["services"][0],
        lambda s: s["status"] == "INACTIVE",
        timeout_s=120.0,
        interval_s=5.0,
    )
    ecs.delete_cluster(cluster=cluster_name)
    deleted = _poll_until(
        lambda: ecs.describe_clusters(clusters=[cluster_name])["clusters"][0],
        lambda c: c["status"] == "INACTIVE",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert deleted["status"] == "INACTIVE", (
        f"expected cluster status=INACTIVE after the positive-control delete succeeded, got {deleted['status']!r}"
    )


def _best_effort_teardown(ctx, cluster_name):
    ecs = ctx.client("ecs")
    try:
        for svc in ecs.list_services(cluster=cluster_name).get("serviceArns", []):
            try:
                ecs.update_service(cluster=cluster_name, service=svc, desiredCount=0)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "ClusterNotFoundException",
                    "NamespaceNotFoundException",
                    "ServiceNotActiveException",
                    "ServiceNotFoundException",
                ):
                    raise
            try:
                ecs.delete_service(cluster=cluster_name, service=svc, force=True)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "ClusterNotFoundException",
                    "ServiceNotFoundException",
                ):
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "NamespaceNotFoundException",
            "ServiceNotActiveException",
            "ServiceNotFoundException",
        ):
            raise
    _drain_and_delete_ecs_cluster(ecs, cluster_name)


def _register_fargate_task_def(ctx, family: str) -> str:
    ecs = ctx.client("ecs")
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": ["sleep", "900"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _default_network_config(ctx) -> tuple[list[str], str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC available in this account/region to attach Fargate ENIs to"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return subnet_ids, sgs[0]["GroupId"]


def _wait_service_steady(ctx, cluster_name: str, service_arn: str, timeout_s: float = 300.0):
    ecs = ctx.client("ecs")

    def probe():
        resp = ecs.describe_services(cluster=cluster_name, services=[service_arn])
        return resp["services"][0] if resp["services"] else None

    def is_steady(svc):
        return (
            svc is not None
            and svc["status"] == "ACTIVE"
            and svc["runningCount"] == svc["desiredCount"]
            and svc["pendingCount"] == 0
        )

    return _poll_until(probe, is_steady, timeout_s=timeout_s, interval_s=5.0)


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")



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
            except ClientError:
                pass
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
