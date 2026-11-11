"""service-deployment-events-ordered."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-deployment-events-ordered"
GROUP = "ordering"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListServiceDeployments / DescribeServiceDeployments return deployment records
    for a service in strict chronological order as new deployments are triggered by
    UpdateService(forceNewDeployment=True)."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, cluster_arn))

    # A service with desiredCount=0 (or the EC2 launch type without registered
    # container instances) never actually places tasks, and real ECS's newer
    # per-deployment tracking (ListServiceDeployments / DescribeServiceDeployments)
    # does not reliably create a distinct ServiceDeployment record for a deployment
    # that has nothing to deploy. Use a real FARGATE task with desiredCount=1 so each
    # forceNewDeployment update actually launches/replaces a task and produces its
    # own trackable ServiceDeployment record.
    net = _default_network(ctx)

    family = ctx.unique_name("sim2real-behav-td-")
    task_def_arn = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "c",
                "image": "public.ecr.aws/docker/library/alpine:3.20",
                "command": ["sleep", "900"],
                "essential": True,
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [net["subnet_id"]],
            "securityGroups": [net["sg_id"]],
            "assignPublicIp": "ENABLED",
        }
    }

    service_name = ctx.unique_name("sim2real-behav-svc-")
    service_arn = ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        taskDefinition=task_def_arn,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
    )["service"]["serviceArn"]
    ctx.on_cleanup(lambda: _safe_delete_service(ctx, cluster_arn, service_arn))

    # A forceNewDeployment issued while the previous deployment is still rolling out
    # can get coalesced into that in-progress deployment on real ECS instead of
    # producing a distinct new ServiceDeployment record. Wait for a *new* PRIMARY
    # deployment id to appear and converge before triggering the next update, so
    # each update is guaranteed to create its own distinguishable deployment.
    #
    # Note: we deliberately do NOT require `len(deployments) == 1` here. On real
    # ECS a superseded deployment can linger in the service's `deployments` list
    # (e.g. pending final cleanup/removal bookkeeping) for a while after it has
    # fully drained, even though it is no longer PRIMARY and is functionally
    # irrelevant. Waiting for that stale entry to disappear is not necessary to
    # know the *new* deployment has settled, and doing so needlessly stalls the
    # check well past its time budget. The real convergence signal is on the
    # PRIMARY deployment object itself: each `deployments[]` entry carries its own
    # id/runningCount/pendingCount/desiredCount, so we can tell a new deployment
    # apart from the previous one and confirm it individually converged.
    #
    # `rolloutState` is not a reliable settlement signal here: on real ECS it is
    # only meaningfully driven for deployments monitored by the deployment circuit
    # breaker, and without the circuit breaker enabled it can simply stay
    # unset/non-COMPLETED indefinitely even though the deployment has actually
    # converged.
    def _primary_deployment(svc):
        for d in svc.get("deployments", []):
            if d.get("status") == "PRIMARY":
                return d
        return None

    def _settled_primary_id(prev_id):
        svc = ecs.describe_services(cluster=cluster_arn, services=[service_arn])["services"][0]
        primary = _primary_deployment(svc)
        if primary is None:
            return None
        if primary["id"] == prev_id:
            return None
        if primary.get("runningCount") == primary.get("desiredCount") and primary.get("pendingCount", 0) == 0:
            return primary["id"]
        return None

    # Real ECS's per-deployment tracking (ListServiceDeployments /
    # DescribeServiceDeployments) only records deployments caused by an actual
    # service *update* (e.g. UpdateService with forceNewDeployment=True, a new
    # task definition revision, etc). The very first rollout that happens as part
    # of CreateService is not itself tracked as a "service deployment" -- it's the
    # service being created, not being *deployed to* a new revision -- so it never
    # gets its own ListServiceDeployments/DescribeServiceDeployments record. Only
    # the `num_updates` explicit forceNewDeployment updates below produce
    # trackable ServiceDeployment records.
    def _list_arns() -> list[str]:
        arns: list[str] = []
        next_token = None
        while True:
            kwargs: dict[str, Any] = {"service": service_arn, "cluster": cluster_arn}
            if next_token:
                kwargs["nextToken"] = next_token
            resp = ecs.list_service_deployments(**kwargs)
            arns.extend(d["serviceDeploymentArn"] for d in resp.get("serviceDeployments", []))
            next_token = resp.get("nextToken")
            if not next_token:
                break
        return arns

    # The service-level runningCount/pendingCount settling above is necessary but not
    # sufficient: real ECS can still coalesce a forceNewDeployment issued too soon after
    # the previous one into that still-in-flight ServiceDeployment record instead of
    # minting an independent one. Rather than guess at a proxy signal for "safe to issue the
    # next update", wait on the actual postcondition this check needs: the listed
    # ServiceDeployment count has grown by one because of the update just issued.
    num_updates = 3
    current_id = _poll_until(
        lambda: _settled_primary_id(None), lambda v: v is not None, timeout_s=180.0, interval_s=5.0
    )
    for i in range(num_updates):
        ecs.update_service(cluster=cluster_arn, service=service_arn, forceNewDeployment=True)
        current_id = _poll_until(
            lambda: _settled_primary_id(current_id), lambda v: v is not None, timeout_s=180.0, interval_s=5.0
        )
        arns = _poll_until(
            _list_arns, lambda a, want=i + 1: len(a) >= want, timeout_s=200.0, interval_s=5.0
        )

    # DescribeServiceDeployments to get authoritative createdAt timestamps, then verify
    # that the order returned by ListServiceDeployments is newest-first by createdAt.
    # ListServiceDeployments returns descending order, so the specific direction is the
    # contract, not "monotonic either way".
    described = ecs.describe_service_deployments(serviceDeploymentArns=arns)["serviceDeployments"]
    by_arn = {d["serviceDeploymentArn"]: d["createdAt"] for d in described}
    timestamps = [by_arn[a] for a in arns]

    assert timestamps == sorted(timestamps, reverse=True), (
        f"ListServiceDeployments must return deployment records newest-first by createdAt: {timestamps}"
    )
    # And timestamps must actually be distinct / increasing, not all identical (a
    # trivial "always sorted" pass on constant data would hide real bugs).
    assert len(set(timestamps)) > 1, "expected distinguishable deployment timestamps across updates"


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _safe_delete_service(ctx, cluster_arn: str, service_arn: str) -> None:
    ecs = ctx.client("ecs")
    try:
        ecs.update_service(cluster=cluster_arn, service=service_arn, desiredCount=0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "NamespaceNotFoundException",
            "ServiceNotActiveException",
            "ServiceNotFoundException",
        ):
            raise
    try:
        ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets in shared network")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group in shared network")
    return {"subnet_id": subnets[0]["SubnetId"], "sg_id": sgs[0]["GroupId"]}


def _safe_delete_cluster(ctx, cluster_arn: str) -> None:
    ecs = ctx.client("ecs")
    _drain_and_delete_ecs_cluster(ecs, cluster_arn)



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
                    "ClusterNotFoundException", "ServiceNotFoundException", "ServiceNotActiveException",
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
