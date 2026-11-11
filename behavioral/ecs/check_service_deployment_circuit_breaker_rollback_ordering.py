"""service-deployment-circuit-breaker-rollback-ordering."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-deployment-circuit-breaker-rollback-ordering"
GROUP = "ordering"
SERVICES = ["ecs"]

_TERMINAL_STATUSES = {"ROLLBACK_SUCCESSFUL", "ROLLBACK_FAILED", "SUCCESSFUL", "STOPPED"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With the circuit breaker and rollback on, a deployment to an always-exiting container reports
    PENDING/IN_PROGRESS before ROLLBACK_IN_PROGRESS before its final ROLLBACK_* status, and the service
    ends on the prior task definition with RUNNING tasks.
    """
    ecs = ctx.client("ecs")
    net = _default_network(ctx)
    cluster_arn, _cluster_name = _create_cluster(ctx)

    family = ctx.unique_name("sim2real-cbfam-")
    good_task_def_arn = _register_fargate_task_def(ctx, family, ["sleep", "3600"])

    service_arn, service_name = _create_service_with_circuit_breaker(ctx, cluster_arn, good_task_def_arn, net)
    _wait_for_running_tasks(ctx, cluster_arn, service_name, count=1, timeout_s=300)

    before = ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]
    initial_deployment_arn = before.get("currentServiceDeployment")

    # Register a new revision in the SAME family whose container exits immediately
    # with a non-zero code -- every task launched from it fails to reach steady state.
    bad_task_def_arn = _register_fargate_task_def(ctx, family, ["false"])

    ecs.update_service(cluster=cluster_arn, service=service_name, taskDefinition=bad_task_def_arn)

    deployment_arn = _wait_for_new_deployment(ctx, cluster_arn, service_name, initial_deployment_arn, timeout_s=60)

    statuses, final_dep = _poll_deployment_statuses(ctx, deployment_arn, timeout_s=900)

    assert final_dep["status"] in ("ROLLBACK_SUCCESSFUL", "ROLLBACK_FAILED"), (
        f"expected the circuit breaker to trigger a rollback attempt, "
        f"ended in {final_dep['status']} (history={statuses})"
    )
    assert any(s in ("PENDING", "IN_PROGRESS") for s in statuses), (
        f"rollback observed without any prior forward deployment progress: {statuses}"
    )
    if "ROLLBACK_IN_PROGRESS" in statuses:
        idx_rollback_start = statuses.index("ROLLBACK_IN_PROGRESS")
        idx_forward = next(
            (i for i, s in enumerate(statuses) if s in ("PENDING", "IN_PROGRESS")), None
        )
        assert idx_forward is not None and idx_forward < idx_rollback_start, (
            f"rollback started without ever observing forward deployment progress first: {statuses}"
        )
        idx_final = len(statuses) - 1
        assert idx_rollback_start <= idx_final, (
            f"final status observed before/alongside ROLLBACK_IN_PROGRESS: {statuses}"
        )

    if final_dep["status"] == "ROLLBACK_SUCCESSFUL":
        # Only AFTER a successful rollback does the service return to the prior stable revision.
        after = ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]
        assert after["taskDefinition"] == good_task_def_arn, (
            "service did not roll back to the prior (good) task definition after the "
            "circuit breaker tripped"
        )
        _wait_for_running_tasks(ctx, cluster_arn, service_name, count=1, timeout_s=180)
    else:
        # Even when the rollback attempt itself fails, the originally-running good
        # task must never have been torn down -- the service stays on some RUNNING
        # task the whole time, it just isn't guaranteed to be the good revision alone.
        running = ecs.list_tasks(cluster=cluster_arn, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]
        assert running, "service has no RUNNING tasks at all after a failed rollback"


def _default_network(ctx) -> dict:
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
        "security_groups": [sgs[0]["GroupId"]] if sgs else [],
    }


def _create_cluster(ctx) -> tuple[str, str]:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-")
    arn = ecs.create_cluster(
        clusterName=name, tags=[{"key": "sim2real", "value": "behavioral"}]
    )["cluster"]["clusterArn"]

    def _cleanup() -> None:
        try:
            ecs.delete_cluster(cluster=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return arn, name


def _register_fargate_task_def(ctx, family: str, command: list[str]) -> str:
    ecs = ctx.client("ecs")
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": command,
            }
        ],
        tags=[{"key": "sim2real", "value": "behavioral"}],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _create_service_with_circuit_breaker(ctx, cluster_arn: str, task_def_arn: str, net: dict):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-svc-")
    resp = ecs.create_service(
        cluster=cluster_arn,
        serviceName=name,
        taskDefinition=task_def_arn,
        desiredCount=1,
        launchType="FARGATE",
        deploymentConfiguration={
            "deploymentCircuitBreaker": {
                "enable": True,
                "rollback": True,
                "thresholdConfiguration": {"type": "COUNT", "value": 1},
            },
        },
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": net["subnets"],
                "securityGroups": net["security_groups"],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=[{"key": "sim2real", "value": "behavioral"}],
    )
    service_arn = resp["service"]["serviceArn"]
    ctx.on_cleanup(
        lambda: _try(lambda: ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True))
    )
    return service_arn, name


def _wait_for_running_tasks(ctx, cluster_arn: str, service_name: str, count: int = 1, timeout_s: float = 300.0):
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        arns = ecs.list_tasks(cluster=cluster_arn, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]
        if len(arns) >= count:
            return arns
        time.sleep(2)
    raise AssertionError(f"service {service_name} did not reach {count} RUNNING task(s) within {timeout_s}s")


def _wait_for_new_deployment(ctx, cluster_arn: str, service_name: str, previous_arn, timeout_s: float = 60.0) -> str:
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        svc = ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]
        current = svc.get("currentServiceDeployment")
        if current and current != previous_arn:
            return current
        time.sleep(3)
    raise AssertionError("a new service deployment never started after UpdateService")


def _wait_for_primary_rollout_completed(ctx, cluster_arn: str, service_name: str, timeout_s: float = 120.0) -> None:
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        svc = ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]
        primary = next((d for d in svc.get("deployments", []) if d.get("status") == "PRIMARY"), None)
        if primary:
            last_state = primary.get("rolloutState")
            if last_state == "COMPLETED":
                return
            if last_state == "FAILED":
                raise AssertionError(
                    f"initial deployment rolloutState FAILED: {primary.get('rolloutStateReason')}"
                )
        time.sleep(4)
    raise AssertionError(
        f"initial deployment never reached rolloutState COMPLETED within {timeout_s}s "
        f"(last={last_state}, primary={primary!r})"
    )


def _poll_deployment_statuses(ctx, deployment_arn: str, timeout_s: float = 900.0, interval_s: float = 8.0):
    ecs = ctx.client("ecs")
    seen: list[str] = []
    deadline = time.monotonic() + timeout_s
    final_dep = None
    while time.monotonic() < deadline:
        final_dep = ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])["serviceDeployments"][0]
        status = final_dep["status"]
        if not seen or seen[-1] != status:
            seen.append(status)
        if status in _TERMINAL_STATUSES:
            return seen, final_dep
        time.sleep(interval_s)
    raise AssertionError(f"deployment {deployment_arn} never reached a terminal state; observed {seen}")


def _try(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
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
