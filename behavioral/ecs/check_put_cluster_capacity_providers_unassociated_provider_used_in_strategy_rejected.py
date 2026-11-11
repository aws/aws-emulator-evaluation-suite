"""put-cluster-capacity-providers-unassociated-provider-used-in-strategy-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-cluster-capacity-providers-unassociated-provider-used-in-strategy-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask rejects a capacityProviderStrategy referencing a provider never associated with the cluster."""
    ecs = ctx.client("ecs")
    _, subnet_id, sg_id = _default_subnet_and_sg(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-unassoc-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name,
        tags=[{"key": "sim2real:check", "value": CHECK}],
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_arn))

    # Associate only FARGATE with the cluster -- FARGATE_SPOT is deliberately left unassociated.
    ecs.put_cluster_capacity_providers(
        cluster=cluster_arn,
        capacityProviders=["FARGATE"],
        defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
    )

    family = ctx.unique_name("sim2real-ecs-unassoc-td-")
    task_def = ecs.register_task_definition(
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
            }
        ],
        tags=[{"key": "sim2real:check", "value": CHECK}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def["taskDefinitionArn"]))

    net_config = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id] if sg_id else [],
            "assignPublicIp": "ENABLED",
        }
    }

    code, message = _error(
        lambda: ecs.run_task(
            cluster=cluster_arn,
            taskDefinition=task_def["taskDefinitionArn"],
            networkConfiguration=net_config,
            capacityProviderStrategy=[{"capacityProvider": "FARGATE_SPOT", "weight": 1}],
            count=1,
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a capacityProviderStrategy naming a provider "
        f"never associated with the cluster, got {code!r}"
    )
    assert message == (
        "The specified capacity provider strategy cannot contain a capacity provider that is not "
        "associated with the cluster. Associate the capacity provider with the cluster or specify "
        "a valid capacity provider and try again."
    ), message

    # Effect absent: no task was launched on the cluster.
    task_arns = ecs.list_tasks(cluster=cluster_arn)["taskArns"]
    assert task_arns == [], f"a task was launched using an unassociated capacity provider: {task_arns}"

    # Positive control: the associated FARGATE provider is accepted.
    good = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_def["taskDefinitionArn"],
        networkConfiguration=net_config,
        capacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
        count=1,
        tags=[{"key": "sim2real:check", "value": CHECK}],
    )
    assert good["tasks"], f"expected a launched task, got failures={good.get('failures')}"
    task_arn = good["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _stop_task_and_wait(ecs, cluster_arn, task_arn))

    # An independent read at the destination, not just the RunTask response echo. A task
    # that RunTask provisionally accepted can still fail to start (e.g. image pull, ENI setup);
    # only describe_tasks reaching RUNNING proves the associated provider actually placed it.
    placed = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0],
        lambda t: t["lastStatus"] in ("RUNNING", "STOPPED"),
        timeout_s=180.0,
        description="task launched via the associated FARGATE provider reaches a terminal launch state",
    )
    assert placed["lastStatus"] == "RUNNING", (
        f"expected the FARGATE-provider task to reach RUNNING, got {placed['lastStatus']!r} "
        f"(stoppedReason={placed.get('stoppedReason')!r})"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, because an emulator accepting input real AWS refuses must fail loudly rather than
    read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _default_subnet_and_sg(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to build an awsvpc network configuration")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available for an awsvpc network configuration")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return vpc_id, subnet_id, sg_id


def _stop_task_and_wait(ecs, cluster_arn, task_arn, timeout_s=45.0):
    try:
        ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real-cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])
        tasks = resp.get("tasks", [])
        if not tasks or tasks[0]["lastStatus"] == "STOPPED":
            return
        time.sleep(3)



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
