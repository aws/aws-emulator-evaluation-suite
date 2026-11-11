"""run-task-overrides-unknown-container-name-rejected."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-task-overrides-unknown-container-name-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask with a containerOverrides entry naming a container that isn't
    present in the task definition is rejected, and no task is created."""
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _default_network(ctx)

    cluster_name = ctx.unique_name("sim2real-badoverride-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-badoverride-td-")
    taskdef = ecs.register_task_definition(
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
                "command": ["sleep", "300"],
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=taskdef))
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[taskdef]))

    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }

    code, message = _refusal(
        lambda: ecs.run_task(
            cluster=cluster_arn,
            taskDefinition=taskdef,
            launchType="FARGATE",
            networkConfiguration=net_cfg,
            overrides={"containerOverrides": [{"name": "does-not-exist", "command": ["echo", "hi"]}]},
            count=1,
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException, got {code!r}"
    )
    assert message == "Override for container named does-not-exist is not a container in the TaskDefinition.", f"refusal message {message!r}"

    # Effect absent: no task was created on the cluster.
    running = ecs.list_tasks(cluster=cluster_arn)["taskArns"]
    assert running == [], f"a task leaked despite the rejected container override: {running}"

    # Positive control: an override naming the real container succeeds.
    resp = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=taskdef,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
        overrides={"containerOverrides": [{"name": "app", "command": ["sleep", "300"]}]},
        count=1,
    )
    assert resp["failures"] == [], f"unexpected failures on a valid container override: {resp['failures']}"
    task_arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=cluster_arn, task=task_arn))

    # Independent terminal read: the accepted override is visible at the destination through
    # DescribeTasks (a different operation than the RunTask call that created it), not just in
    # RunTask's own response.
    described = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"]
    assert len(described) == 1, f"expected the accepted task to be independently readable, got {described}"
    described_overrides = described[0].get("overrides", {}).get("containerOverrides", [])
    described_names = [co.get("name") for co in described_overrides]
    assert "app" in described_names, (
        f"expected the real container's override to be recorded on the task, got {described_names}"
    )


# ===== helpers =====
def _refusal(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because a target accepting what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch a Fargate task")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no network subnet available to launch a Fargate task")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group available to launch a Fargate task")
    return subnets[0]["SubnetId"], sgs[0]["GroupId"]



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
                if exc.response["Error"]["Code"] not in ("ServiceNotFoundException", "ServiceNotActiveException"):
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

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
