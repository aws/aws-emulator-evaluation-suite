"""e2e-service-deployment-rollback-on-failed-taskdef."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-service-deployment-rollback-on-failed-taskdef"
GROUP = "state-machine"
SERVICES = ["ecs"]



@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With the deployment circuit breaker and rollback enabled, updating a service to a task
    definition that can never reach RUNNING ends that deployment FAILED by the circuit breaker
    and rolls the running tasks back to the prior revision, with no task of the bad one left."""
    ecs = ctx.client("ecs")
    net = _default_network(ctx)
    _ensure_ecs_slr(ctx)


    cluster = ctx.unique_name("sim2real-ecs-rollback-cluster-")
    ecs.create_cluster(clusterName=cluster)
    ctx.on_cleanup(lambda: _delete_cluster_retry(ecs, cluster))

    family = ctx.unique_name("sim2real-ecs-rollback-td-")
    good_arn = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "command": ["sleep", "3600"],
                "essential": True,
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, good_arn))

    service_name = ctx.unique_name("sim2real-ecs-rollback-svc-")
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": net["subnet_ids"][:1],
            "securityGroups": [net["sg_id"]],
            "assignPublicIp": "ENABLED",
        }
    }
    _retry_slr(lambda: ecs.create_service(
        cluster=cluster,
        serviceName=service_name,
        taskDefinition=good_arn,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
        deploymentConfiguration={"deploymentCircuitBreaker": {"enable": True, "rollback": True}},
    ))

    def _cleanup_service() -> None:
        ecs.update_service(cluster=cluster, service=service_name, desiredCount=0)
        _poll_until(
            lambda: ecs.describe_services(cluster=cluster, services=[service_name])["services"][0]["runningCount"],
            lambda n: n == 0,
            timeout_s=180,
            interval_s=5,
        )
        ecs.delete_service(cluster=cluster, service=service_name, force=True)
        _poll_until(
            lambda: ecs.describe_services(cluster=cluster, services=[service_name])["services"][0]["status"],
            lambda s: s == "INACTIVE",
            timeout_s=600,
            interval_s=5,
        )

    ctx.on_cleanup(_cleanup_service)

    def _running_task_defs():
        arns = ecs.list_tasks(cluster=cluster, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]
        if not arns:
            return []
        tasks = ecs.describe_tasks(cluster=cluster, tasks=arns)["tasks"]
        return [t["taskDefinitionArn"] for t in tasks]

    _poll_until(
        _running_task_defs, lambda tds: len(tds) == 1 and tds[0] == good_arn, timeout_s=300, interval_s=10
    )

    bad_arn = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "main",
                "image": "sim2real-nonexistent-image-should-fail-to-pull:1.0",
                "essential": True,
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, bad_arn))

    ecs.update_service(cluster=cluster, service=service_name, taskDefinition=bad_arn)

    # Prove the bad revision was actually attempted and that ECS's OWN circuit breaker is what
    # detected the failure -- without this, a target that no-ops UpdateService (or ignores the
    # circuit-breaker config entirely) would pass identically, since the tasks would simply have
    # stayed on good_arn the whole time.
    def _bad_deployment():
        deployments = ecs.describe_services(cluster=cluster, services=[service_name])["services"][0]["deployments"]
        matches = [d for d in deployments if d["taskDefinition"] == bad_arn]
        return matches[0] if matches else None

    failed_deployment = _poll_until(
        _bad_deployment, lambda d: d is not None and d.get("rolloutState") == "FAILED", timeout_s=900, interval_s=15
    )
    reason = (failed_deployment.get("rolloutStateReason") or "").lower()
    assert "circuit breaker" in reason, (
        f"expected the failed deployment's rolloutStateReason to attribute the failure to the "
        f"circuit breaker, got {failed_deployment.get('rolloutStateReason')!r}"
    )

    def _steady_state_task_def():
        arns = ecs.list_tasks(cluster=cluster, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]
        if not arns:
            return None
        tds = {t["taskDefinitionArn"] for t in ecs.describe_tasks(cluster=cluster, tasks=arns)["tasks"]}
        return next(iter(tds)) if len(tds) == 1 else None

    rolled_back_to = _poll_until(_steady_state_task_def, lambda td: td == good_arn, timeout_s=900, interval_s=15)
    assert rolled_back_to == good_arn, (
        f"expected running tasks to settle back on the prior stable revision {good_arn}, got {rolled_back_to!r}"
    )

    # No task of the rejected revision may survive the rollback.
    surviving_arns = ecs.list_tasks(cluster=cluster, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]
    for task in ecs.describe_tasks(cluster=cluster, tasks=surviving_arns)["tasks"]:
        assert task["taskDefinitionArn"] != bad_arn, (
            f"task {task['taskArn']} is still running the rejected revision {bad_arn} after rollback"
        )

    # The classic circuit-breaker rollback signal: DescribeServices settles back to a single
    # steady-state deployment on the prior stable revision, COMPLETED (not just "some task is
    # RUNNING on good_arn" — the deployment bookkeeping itself must reflect the rollback).
    def _primary_deployment():
        deployments = ecs.describe_services(cluster=cluster, services=[service_name])["services"][0]["deployments"]
        matches = [d for d in deployments if d["taskDefinition"] == good_arn]
        return matches[0] if matches else None

    primary = _poll_until(
        _primary_deployment,
        lambda d: d is not None and d.get("runningCount") == d.get("desiredCount") and d.get("runningCount", 0) > 0,
        timeout_s=300,
        interval_s=10,
    )
    assert primary["taskDefinition"] == good_arn, (
        f"expected the PRIMARY deployment to reference {good_arn}, got {primary['taskDefinition']!r}"
    )
    assert primary["runningCount"] == primary["desiredCount"] == 1, (
        f"expected runningCount == desiredCount == 1, got runningCount={primary['runningCount']!r} "
        f"desiredCount={primary['desiredCount']!r}"
    )

    # ListServiceDeployments/DescribeServiceDeployments is Amazon ECS's newer unified
    # deployment-history view; exercise it for observability of this same rollout (its status
    # semantics for a classic rolling+circuit-breaker rollback differ from blue/green service
    # revisions, so we only assert the API surfaces a well-formed, matching record here).
    summaries = ecs.list_service_deployments(cluster=cluster, service=service_name)["serviceDeployments"]
    assert summaries, "expected at least one tracked service deployment for this service"
    detail = ecs.describe_service_deployments(
        serviceDeploymentArns=[summaries[0]["serviceDeploymentArn"]]
    )["serviceDeployments"][0]
    svc_arn = ecs.describe_services(cluster=cluster, services=[service_name])["services"][0]["serviceArn"]
    assert detail["serviceArn"] == svc_arn, (
        f"expected the tracked service deployment to reference {svc_arn}, got {detail['serviceArn']!r}"
    )





# ===== helpers =====
def _ensure_ecs_slr(ctx) -> None:
    """Make sure AWSServiceRoleForECS exists so CreateService doesn't hit
    'Unable to assume the service linked role' on a fresh account. Propagation of a
    freshly-created role is bounded by _retry_slr's retry around create_service, not a sleep here."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("InvalidInput",):
            raise


def _retry_slr(fn, timeout_s=90.0, interval_s=5.0):
    """Retry an ECS call that can transiently fail with
    'Unable to assume the service linked role' right after account/role creation."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            msg = str(e)
            if "Unable to assume the service linked role" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
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
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    public = [s["SubnetId"] for s in subnets if s.get("MapPublicIpOnLaunch")]
    subnet_ids = public or [s["SubnetId"] for s in subnets]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sgs[0]["GroupId"]}


def _delete_cluster_retry(ecs, cluster_name, timeout_s=90.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterContainsTasksException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
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
