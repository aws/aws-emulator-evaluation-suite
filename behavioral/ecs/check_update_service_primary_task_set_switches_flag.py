"""update-service-primary-task-set-switches-flag."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-service-primary-task-set-switches-flag"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateServicePrimaryTaskSet flips which task set is PRIMARY (the other becomes ACTIVE),
    as reflected by DescribeTaskSets, for an EXTERNAL-deployment-controller service."""

    ecs = ctx.client("ecs")
    subnets, sg_id = _default_network(ctx)

    resource_tags = [{"key": "sim2real-check", "value": CHECK}]

    cluster_arn = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-ecs-"), tags=resource_tags
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_free(ecs, cluster_arn))
    ecs.put_cluster_capacity_providers(
        cluster=cluster_arn, capacityProviders=["FARGATE"], defaultCapacityProviderStrategy=[]
    )

    family = ctx.unique_name("sim2real-ts-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36", "essential": True, "command": ["sleep", "3600"]}
        ],
        tags=resource_tags,
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    service_name = ctx.unique_name("sim2real-ext-svc-")
    ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        desiredCount=0,
        deploymentController={"type": "EXTERNAL"},
        tags=resource_tags,
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_arn, service=service_name, force=True))

    net_cfg = {"awsvpcConfiguration": {"subnets": subnets, "securityGroups": [sg_id], "assignPublicIp": "ENABLED"}}

    def _create_task_set():
        ts = ecs.create_task_set(
            cluster=cluster_arn,
            service=service_name,
            taskDefinition=td_arn,
            launchType="FARGATE",
            networkConfiguration=net_cfg,
            scale={"value": 0.0, "unit": "PERCENT"},
            tags=resource_tags,
        )["taskSet"]
        ctx.on_cleanup(
            lambda arn=ts["taskSetArn"]: ecs.delete_task_set(cluster=cluster_arn, service=service_name, taskSet=arn, force=True)
        )
        return ts

    try:
        ts1 = _create_task_set()
    except ClientError as e:
        raise AssertionError(f"unreachable: CreateTaskSet not usable in this environment: {e}")

    # For an EXTERNAL deployment controller, ECS does NOT auto-promote a newly created task set
    # to PRIMARY the way it does for the ECS-managed controller -- the caller is responsible for
    # explicitly designating the primary task set via UpdateServicePrimaryTaskSet, even for the
    # very first task set for the service. Promote ts1 explicitly before creating ts2 so the
    # "before" baseline (ts1 PRIMARY / ts2 ACTIVE) is actually reachable instead of waiting
    # forever for an automatic promotion that never happens.
    ecs.update_service_primary_task_set(cluster=cluster_arn, service=service_name, primaryTaskSet=ts1["taskSetArn"])

    ts2 = _create_task_set()

    def _statuses():
        sets = ecs.describe_task_sets(cluster=cluster_arn, service=service_name, taskSets=[ts1["taskSetArn"], ts2["taskSetArn"]])[
            "taskSets"
        ]
        return {s["taskSetArn"]: s["status"] for s in sets}

    # ts1 was just explicitly promoted above and ts2 was created afterward (so it defaults to
    # ACTIVE, not PRIMARY) -- poll DescribeTaskSets only to let that settle, not to wait on any
    # automatic designation.
    before = _poll_until(
        _statuses,
        lambda s: s.get(ts1["taskSetArn"]) == "PRIMARY" and s.get(ts2["taskSetArn"]) == "ACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    assert before[ts1["taskSetArn"]] == "PRIMARY", f"expected ts1 PRIMARY before switch, got {before}"
    assert before[ts2["taskSetArn"]] == "ACTIVE", f"expected ts2 ACTIVE before switch, got {before}"

    ecs.update_service_primary_task_set(cluster=cluster_arn, service=service_name, primaryTaskSet=ts2["taskSetArn"])

    after = _poll_until(
        _statuses,
        lambda s: s.get(ts2["taskSetArn"]) == "PRIMARY" and s.get(ts1["taskSetArn"]) == "ACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    assert after[ts2["taskSetArn"]] == "PRIMARY", after
    assert after[ts1["taskSetArn"]] == "ACTIVE", after


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
