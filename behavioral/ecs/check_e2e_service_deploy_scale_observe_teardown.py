"""e2e-service-deploy-scale-observe-teardown."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-service-deploy-scale-observe-teardown"
GROUP = "e2e"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Create a Fargate service, converge RunningCount 2->4 on UpdateService, then force-delete the
    service and cluster and confirm both reach a terminal INACTIVE/absent state."""
    ecs = ctx.client("ecs")
    subnet_ids, sg_id = _default_networking(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-e2e-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_cluster(cluster=cluster_name)))

    family = ctx.unique_name("sim2real-ecs-e2e-td-")
    td = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                # small, no-pull-surprises image and no port mappings/health checks: minimizes
                # time-to-RUNNING so the whole 2->4 convergence fits the harness's 300s budget.
                "name": "web",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sh", "-c", "sleep 3600"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    service_name = ctx.unique_name("sim2real-ecs-e2e-svc-")
    ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=td_arn,
        desiredCount=2,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnet_ids,
                "securityGroups": [sg_id],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True))
    )

    def _describe():
        return ecs.describe_services(cluster=cluster_name, services=[service_name])["services"][0]

    # Poll budgets are kept tight and summed deliberately so both Fargate convergences
    # (2 tasks, then +2 more) leave headroom for setup and teardown within the run budget.
    steady = _poll_until(
        _describe,
        lambda svc: svc["runningCount"] == 2 and svc["pendingCount"] == 0,
        timeout_s=110.0,
        interval_s=5.0,
    )
    assert steady["runningCount"] == 2, f"expected runningCount 2 at steady state, got {steady['runningCount']!r}"

    ecs.update_service(cluster=cluster_name, service=service_name, desiredCount=4)
    scaled = _poll_until(
        _describe,
        lambda svc: svc["runningCount"] == 4 and svc["pendingCount"] == 0,
        timeout_s=110.0,
        interval_s=5.0,
    )
    assert scaled["desiredCount"] == 4 and scaled["runningCount"] == 4, (
        f"expected desiredCount=4 and runningCount=4 after scale-up, "
        f"got desiredCount={scaled['desiredCount']!r} runningCount={scaled['runningCount']!r}"
    )

    ecs.delete_service(cluster=cluster_name, service=service_name, force=True)

    def _service_status_or_gone():
        resp = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"]
        return "GONE" if not resp else resp[0]["status"]

    _poll_until(
        _service_status_or_gone, lambda s: s in ("INACTIVE", "GONE"), timeout_s=170.0, interval_s=5.0
    )

    def _cluster_counts():
        return ecs.describe_clusters(clusters=[cluster_name])["clusters"][0]

    _poll_until(
        _cluster_counts,
        lambda c: c["runningTasksCount"] == 0 and c["activeServicesCount"] == 0,
        timeout_s=20.0,
        interval_s=5.0,
    )

    delete_resp = ecs.delete_cluster(cluster=cluster_name)["cluster"]
    assert delete_resp["status"] == "INACTIVE", (
        f"expected DeleteCluster's own response to report INACTIVE, got {delete_resp['status']!r}"
    )

    def _cluster_status_or_gone():
        resp = ecs.describe_clusters(clusters=[cluster_name])["clusters"]
        return "GONE" if not resp else resp[0]["status"]

    _poll_until(_cluster_status_or_gone, lambda s: s in ("INACTIVE", "GONE"), timeout_s=10.0, interval_s=3.0)


# ===== helpers =====

def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _default_networking(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region; required to build the awsvpc "
            "networkConfiguration (subnets + security group) this check needs"
        )
    vpc = vpcs[0]
    vpc_id = vpc["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    return subnet_ids, sg_id


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
