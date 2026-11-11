"""service-revisions-tracked-across-updates."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-revisions-tracked-across-updates"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Multiple UpdateService calls each generate a distinct, retrievable service revision that
    DescribeServiceRevisions can describe, tracking the task definition used by each."""
    ecs = ctx.client("ecs")
    net = _default_network(ctx)

    cluster_name = ctx.unique_name("sim2real-behav-rev-cluster-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-behav-rev-task-")
    task_defs = [_register_sleep_task_def(ctx, family) for _ in range(4)]
    for td in task_defs:
        ctx.on_cleanup(lambda td=td: _retire_task_definition(ecs, td))

    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": net["subnet_ids"],
            "securityGroups": [net["security_group_id"]] if net["security_group_id"] else [],
            "assignPublicIp": "ENABLED",
        }
    }

    service_name = ctx.unique_name("sim2real-behav-rev-svc-")
    ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        taskDefinition=task_defs[0],
        desiredCount=0,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
    )
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: ecs.delete_service(cluster=cluster_arn, service=service_name, force=True)
        )
    )
    # CreateService itself mints the first deployment/revision. If it hasn't settled
    # before the first UpdateService fires, real AWS can coalesce the two into a single
    # deployment instead of recording one per call -- the same risk the loop below
    # already guards against for the update-to-update case.
    _wait_for_steady(ecs, cluster_arn, service_name, timeout_s=120)

    for td in task_defs[1:]:
        ecs.update_service(cluster=cluster_arn, service=service_name, taskDefinition=td)
        # Firing UpdateService calls back-to-back with no wait risks real AWS
        # coalescing them into a single in-flight deployment instead of recording
        # a distinct deployment per call. Wait for each update's deployment to
        # settle before issuing the next one.
        _wait_for_steady(ecs, cluster_arn, service_name, timeout_s=120)

    deployments = _poll_until(
        lambda: ecs.list_service_deployments(cluster=cluster_arn, service=service_name)[
            "serviceDeployments"
        ],
        lambda ds: len(ds) >= len(task_defs),
        timeout_s=180,
        interval_s=3,
    )
    deployments_sorted = sorted(deployments, key=lambda d: d["createdAt"])
    assert len(deployments_sorted) == len(task_defs), (
        f"expected exactly {len(task_defs)} service deployments (1 create + "
        f"{len(task_defs) - 1} updates), got {len(deployments_sorted)}"
    )
    deployment_arns_in_order = [d["serviceDeploymentArn"] for d in deployments_sorted]
    described = ecs.describe_service_deployments(serviceDeploymentArns=deployment_arns_in_order)
    described_by_arn = {d["serviceDeploymentArn"]: d for d in described["serviceDeployments"]}
    revision_arns_in_order = [
        described_by_arn[arn]["targetServiceRevision"]["arn"] for arn in deployment_arns_in_order
    ]
    assert len(set(revision_arns_in_order)) == len(task_defs), (
        f"expected {len(task_defs)} distinct service revisions, got {revision_arns_in_order!r}"
    )

    revisions = ecs.describe_service_revisions(serviceRevisionArns=revision_arns_in_order)
    assert not revisions["failures"], revisions["failures"]
    by_arn = {r["serviceRevisionArn"]: r["taskDefinition"] for r in revisions["serviceRevisions"]}
    task_def_sequence = [by_arn[arn] for arn in revision_arns_in_order]
    assert task_def_sequence == task_defs, (
        f"expected chronological revision->taskDefinition sequence {task_def_sequence} "
        f"to match update order {task_defs}"
    )


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


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_for_steady(ecs, cluster_arn, service_name, timeout_s=120.0):
    def probe():
        return ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]

    def done(svc):
        primary = next((d for d in svc.get("deployments", []) if d.get("status") == "PRIMARY"), None)
        return bool(primary) and primary.get("rolloutState") == "COMPLETED"

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=5)


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
