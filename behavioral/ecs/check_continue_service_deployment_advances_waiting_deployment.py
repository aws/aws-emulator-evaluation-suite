"""continue-service-deployment-advances-waiting-deployment."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "continue-service-deployment-advances-waiting-deployment"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A BLUE_GREEN deployment with a PRE_SCALE_UP pause hook waits at AWAITING_ACTION;
    ContinueServiceDeployment resolves the hook and the deployment reaches SUCCESSFUL."""

    ecs = ctx.client("ecs")
    subnets, sg_id = _default_network(ctx)

    cluster_arn = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-ecs-"))["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_free(ecs, cluster_arn))
    # NOTE: no PutClusterCapacityProviders call here -- it's only needed when a service/task
    # relies on the cluster's *default* capacityProviderStrategy. Every task in this check
    # requests launchType="FARGATE" explicitly, which works on any cluster without an
    # explicit capacity-provider association. Making that call anyway would pay for the
    # AWSServiceRoleForECS service-linked-role creation/propagation retry loop (up to ~120s on an
    # account that had never used ECS capacity providers before), on top of the inherently slow
    # blue/green transition under test.

    net_cfg = {"awsvpcConfiguration": {"subnets": subnets, "securityGroups": [sg_id], "assignPublicIp": "ENABLED"}}

    def _register_td(tag):
        family = ctx.unique_name("sim2real-bg-td-")
        arn = ecs.register_task_definition(
            family=family,
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            cpu="256",
            memory="512",
            containerDefinitions=[
                {
                    "name": "app",
                    "image": "public.ecr.aws/docker/library/busybox:1.36",
                    "essential": True,
                    "command": ["sh", "-c", f"echo {tag}; sleep 3600"],
                    # busybox ignores SIGTERM, so ECS would otherwise wait the full default 30s
                    # stopTimeout before SIGKILL-ing each old (blue) task during the swap's drain
                    # phase -- 2s is the minimum Fargate allows and keeps the blue-task drain fast.
                    "stopTimeout": 2,
                }
            ],
        )["taskDefinition"]["taskDefinitionArn"]
        ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
        return arn

    td_v1 = _register_td("v1")

    service_name = ctx.unique_name("sim2real-bg-svc-")
    try:
        ecs.create_service(
            cluster=cluster_arn,
            serviceName=service_name,
            taskDefinition=td_v1,
            desiredCount=1,
            launchType="FARGATE",
            networkConfiguration=net_cfg,
            deploymentController={"type": "ECS"},
        )
    except ClientError as e:
        raise AssertionError(f"unreachable: CreateService not usable in this environment: {e}")
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_arn, service=service_name, force=True))

    # The initial deployment deliberately uses the default (ROLLING) strategy rather than
    # BLUE_GREEN -- it only needs to reach a stable ACTIVE service before the BLUE_GREEN
    # transition under test begins.
    # Key off runningCount==desiredCount (the earliest real signal the task is up) rather than
    # waiting for rolloutState=="COMPLETED": with a single deployment and no load balancer,
    # COMPLETED only follows once ECS's own rollout-state bookkeeping catches up to that fact --
    # a real (if usually small) extra lag that's pure setup overhead here, not anything this check
    # asserts on.
    _poll_until(
        lambda: ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]["deployments"],
        lambda deps: len(deps) == 1 and deps[0]["runningCount"] == deps[0]["desiredCount"] == 1,
        timeout_s=90,
        interval_s=3,
    )

    def _latest_deployment_arn():
        deployments = ecs.list_service_deployments(service=service_name, cluster=cluster_arn)["serviceDeployments"]
        deployments.sort(key=lambda d: d["createdAt"], reverse=True)
        return deployments[0]["serviceDeploymentArn"]

    # capture the ARN of the (already-stable) initial deployment so we can reliably
    # distinguish it from the new BLUE_GREEN deployment created by the upcoming update_service
    # call -- list_service_deployments can otherwise still return only the old, already-resolved
    # deployment for a little while after the update is submitted, which would make us watch
    # the wrong (already-resolved) deployment's lifecycle hooks forever.
    initial_deployment_arn = _latest_deployment_arn()

    td_v2 = _register_td("v2")

    try:
        ecs.update_service(
            cluster=cluster_arn,
            service=service_name,
            taskDefinition=td_v2,
            deploymentConfiguration={
                "strategy": "BLUE_GREEN",
                # Explicitly zero out any post-traffic-shift bake period: this check only asserts
                # that CONTINUE resolves the PRE_SCALE_UP hook and the deployment subsequently
                # reaches a terminal SUCCESSFUL state, not that a bake window elapses first.
                "bakeTimeInMinutes": 0,
                "lifecycleHooks": [
                    {
                        "lifecycleStages": ["PRE_SCALE_UP"],
                        "targetType": "PAUSE",
                        "timeoutConfiguration": {"timeoutInMinutes": 60, "action": "CONTINUE"},
                    }
                ],
            },
        )
    except ClientError as e:
        raise AssertionError(f"unreachable: BLUE_GREEN pause lifecycle hooks not usable in this environment: {e}")

    deployment_arn = _poll_until(
        _latest_deployment_arn, lambda a: a is not None and a != initial_deployment_arn, timeout_s=30, interval_s=3
    )

    def _hook_details():
        desc = ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])["serviceDeployments"][0]
        return desc.get("lifecycleHookDetails", [])

    def _awaiting_hook():
        for h in _hook_details():
            if h["status"] == "AWAITING_ACTION":
                return h
        return None

    hook = _poll_until(_awaiting_hook, lambda h: h is not None, timeout_s=90, interval_s=3)
    assert hook["targetType"] == "PAUSE", f"expected PAUSE hook, got {hook['targetType']}"
    hook_id = hook["hookId"]

    ecs.continue_service_deployment(serviceDeploymentArn=deployment_arn, hookId=hook_id, action="CONTINUE")

    def _hook_resolved():
        for h in _hook_details():
            if h["hookId"] == hook_id:
                return h["status"]
        return None

    resolved_status = _poll_until(
        _hook_resolved, lambda s: s in ("SUCCEEDED", "FAILED", "TIMED_OUT"), timeout_s=60, interval_s=3
    )
    assert resolved_status == "SUCCEEDED", resolved_status

    # On real AWS, once the PAUSE hook is resolved the deployment still has to scale up the new
    # (green) task set, swap traffic and drain the old (blue) task set before it reaches a
    # terminal state, which can take minutes; the bound below is generous.
    final_deployment_status = _poll_until(
        lambda: ecs.describe_service_deployments(serviceDeploymentArns=[deployment_arn])["serviceDeployments"][0]["status"],
        lambda s: s in ("SUCCESSFUL", "ROLLBACK_SUCCESSFUL", "ROLLBACK_FAILED", "STOPPED"),
        timeout_s=450,
        interval_s=5,
    )
    assert final_deployment_status == "SUCCESSFUL", final_deployment_status


# ===== helpers =====
def _poll_until(probe, predicate, timeout_s=120, interval_s=3):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _default_network(ctx):

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("unreachable: no shared network VPC available")
    vpc_id = vpcs[0]["VpcId"]
    subnets = [s["SubnetId"] for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]][:2]
    if not subnets:
        raise AssertionError("unreachable: shared network has no subnets")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("unreachable: shared network has no default security group")
    return subnets, sgs[0]["GroupId"]


def _delete_cluster_when_free(ecs, cluster, timeout_s=600.0, interval_s=15.0):
    """Delete an ECS cluster, retrying while its capacity providers, tasks or attachments still hold it."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ClusterNotFoundException":
                return
            if code not in ("ClientException", "ClusterContainsTasksException", "UpdateInProgressException",
                            "ClusterContainsServicesException", "ClusterContainsContainerInstancesException") \
                    or time.monotonic() >= deadline:
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
