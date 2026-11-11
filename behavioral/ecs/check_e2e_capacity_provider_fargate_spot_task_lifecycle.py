"""e2e-capacity-provider-fargate-spot-task-lifecycle."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-capacity-provider-fargate-spot-task-lifecycle"
GROUP = "e2e"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """With FARGATE and FARGATE_SPOT associated, RunTask on FARGATE_SPOT reaches RUNNING on that
    provider and StopTask STOPPED; disassociating leaves no providers, and after DeleteCluster no
    task remains."""
    ecs = ctx.client("ecs")
    net = _default_network_config(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-spot-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: ecs.delete_cluster(cluster=cluster_arn)))

    _ensure_ecs_service_linked_role(ctx)
    _call_with_slr_retry(
        lambda: ecs.put_cluster_capacity_providers(
            cluster=cluster_arn,
            capacityProviders=["FARGATE", "FARGATE_SPOT"],
            defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE_SPOT", "weight": 1}],
        )
    )
    cluster_after_assoc = _poll_until(
        lambda: ecs.describe_clusters(clusters=[cluster_arn])["clusters"][0],
        lambda c: set(c["capacityProviders"]) == {"FARGATE", "FARGATE_SPOT"},
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert set(cluster_after_assoc["capacityProviders"]) == {"FARGATE", "FARGATE_SPOT"}, (
        f"expected capacityProviders={{FARGATE, FARGATE_SPOT}}, got {cluster_after_assoc['capacityProviders']}"
    )

    family = ctx.unique_name("sim2real-ecs-spot-td-")
    task_def_arn = _register_sleep_task_def(ctx, family)
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    task_arn = _run_task_with_retry(
        ctx,
        cluster_arn=cluster_arn,
        task_def_arn=task_def_arn,
        net=net,
        capacity_provider_strategy=[{"capacityProvider": "FARGATE_SPOT", "weight": 1}],
    )
    ctx.on_cleanup(lambda: _ignore(lambda: ecs.stop_task(cluster=cluster_arn, task=task_arn)))

    def _describe_task() -> dict:
        return ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]

    running_task = _poll_until(
        _describe_task,
        lambda t: t["lastStatus"] in ("RUNNING", "STOPPED"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert running_task["lastStatus"] == "RUNNING", (
        f"task did not reach RUNNING (stopped reason: {running_task.get('stoppedReason')})"
    )
    assert running_task["capacityProviderName"] == "FARGATE_SPOT", (
        f"expected capacityProviderName=FARGATE_SPOT, got {running_task.get('capacityProviderName')}"
    )

    ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real-teardown")
    stopped_task = _poll_until(
        _describe_task, lambda t: t["lastStatus"] == "STOPPED", timeout_s=180.0, interval_s=5.0
    )
    assert stopped_task["lastStatus"] == "STOPPED", (
        f"expected lastStatus=STOPPED after StopTask, got {stopped_task['lastStatus']}"
    )

    # Disassociate the capacity providers now that nothing uses them, then delete the cluster.
    _call_with_slr_retry(
        lambda: ecs.put_cluster_capacity_providers(
            cluster=cluster_arn, capacityProviders=[], defaultCapacityProviderStrategy=[]
        )
    )
    cluster_after = _poll_until(
        lambda: ecs.describe_clusters(clusters=[cluster_arn])["clusters"][0],
        lambda c: c["capacityProviders"] == [],
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert cluster_after["capacityProviders"] == [], (
        f"expected capacityProviders=[] after disassociation, got {cluster_after['capacityProviders']}"
    )

    _call_with_slr_retry(lambda: ecs.delete_cluster(cluster=cluster_arn))

    def _describe_cluster() -> dict:
        clusters = ecs.describe_clusters(clusters=[cluster_arn])["clusters"]
        return clusters[0] if clusters else {"status": "GONE"}

    final = _poll_until(
        _describe_cluster,
        lambda c: c["status"] in ("INACTIVE", "GONE"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert final["status"] in ("INACTIVE", "GONE"), (
        f"expected cluster status INACTIVE or GONE after DeleteCluster, got {final['status']}"
    )

    remaining_tasks = ecs.list_tasks(cluster=cluster_arn)["taskArns"]
    assert remaining_tasks == [], "no orphaned tasks should remain after teardown"


def _ignore(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _default_network_config(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to launch Fargate tasks")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to launch Fargate tasks into")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return {
        "subnets": [s["SubnetId"] for s in subnets[:2]],
        "securityGroups": [sgs[0]["GroupId"]] if sgs else [],
    }


def _register_sleep_task_def(ctx, family, command=None):
    ecs = ctx.client("ecs")
    container = {
        "name": "app",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "command": command or ["sleep", "1800"],
        "essential": True,
    }
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[container],
    )
    return resp["taskDefinition"]["taskDefinitionArn"]


def _ensure_ecs_service_linked_role(ctx) -> None:
    """Proactively create AWSServiceRoleForECS so PutClusterCapacityProviders doesn't race the
    just-in-time SLR creation on a fresh account (fresh accounts otherwise see 'Unable to
    assume the service linked role' on the first ever ECS cluster capacity-provider call)."""
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except Exception:
        pass


def _call_with_slr_retry(fn, *, timeout_s=90.0, interval_s=5.0):
    """Retry an ECS call that can transiently fail with InvalidParameterException
    ('Unable to assume the service linked role...') while AWSServiceRoleForECS propagates, or
    with UpdateInProgressException ('cluster is in a busy state') while a prior cluster update
    is still settling."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            msg = e.response.get("Error", {}).get("Message", "")
            retriable = "service linked role" in msg.lower() or code == "UpdateInProgressException"
            if not retriable or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _run_task_with_retry(ctx, *, cluster_arn, task_def_arn, net, capacity_provider_strategy):
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + 90.0
    last_code = None
    while time.monotonic() < deadline:
        resp = ecs.run_task(
            cluster=cluster_arn,
            taskDefinition=task_def_arn,
            count=1,
            capacityProviderStrategy=capacity_provider_strategy,
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": net["subnets"],
                    "securityGroups": net["securityGroups"],
                    "assignPublicIp": "ENABLED",
                }
            },
        )
        if resp["tasks"]:
            return resp["tasks"][0]["taskArn"]
        last_code = resp["failures"][0]["reason"] if resp.get("failures") else "unknown"
        time.sleep(5)
    raise AssertionError(f"RunTask never succeeded (last failure reason: {last_code})")


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

