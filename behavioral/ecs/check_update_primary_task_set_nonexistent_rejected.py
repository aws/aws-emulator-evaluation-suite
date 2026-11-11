"""update-primary-task-set-nonexistent-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-primary-task-set-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateServicePrimaryTaskSet against a task set ARN that doesn't exist is rejected with
    TaskSetNotFoundException, and the service's real (only) task set keeps its PRIMARY
    designation unchanged (the forbidden effect doesn't happen)."""

    ecs = ctx.client("ecs")
    subnets, sg_id = _default_network(ctx)

    cluster_arn = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-ecs-"), tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(ecs, cluster_arn))
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
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    service_name = ctx.unique_name("sim2real-ext-svc-")
    ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        desiredCount=0,
        deploymentController={"type": "EXTERNAL"},
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_arn, service=service_name, force=True))

    net_cfg = {"awsvpcConfiguration": {"subnets": subnets, "securityGroups": [sg_id], "assignPublicIp": "ENABLED"}}
    try:
        ts = ecs.create_task_set(
            cluster=cluster_arn,
            service=service_name,
            taskDefinition=td_arn,
            launchType="FARGATE",
            networkConfiguration=net_cfg,
            scale={"value": 0.0, "unit": "PERCENT"},
            tags=[{"key": "sim2real", "value": "true"}],
        )["taskSet"]
    except ClientError as e:
        raise AssertionError(f"unreachable: CreateTaskSet not usable in this environment: {e}")
    ts_arn = ts["taskSetArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_set(cluster=cluster_arn, service=service_name, taskSet=ts_arn, force=True))
    # For an EXTERNAL deployment controller, ECS does NOT auto-promote a newly created task set
    # to PRIMARY the way it does for the ECS-managed controller -- the caller (whatever external
    # system drives the deployment) is responsible for explicitly designating the primary task
    # set via UpdateServicePrimaryTaskSet, even for the very first task set. Do that here so the
    # subsequent negative assertion is testing what it claims to (a rejected update against a
    # real, PRIMARY task set), rather than waiting forever for an automatic promotion that never
    # happens.
    ecs.update_service_primary_task_set(cluster=cluster_arn, service=service_name, primaryTaskSet=ts_arn)
    ts = _poll_until(
        lambda: ecs.describe_task_sets(cluster=cluster_arn, service=service_name, taskSets=[ts_arn])["taskSets"][0],
        lambda t: t["status"] == "PRIMARY",
        timeout_s=60,
        interval_s=3,
    )
    assert ts["status"] == "PRIMARY", f"positive control: expected PRIMARY after explicit designation, got {ts['status']}"

    # A real taskSetArn's final path component isn't a bare opaque token (e.g. it's of the form
    # "ecs-svc/<digits>"); blindly replacing everything after the last "/"
    # drops that structure and produces a syntactically-malformed ARN, which
    # ECS rejects as InvalidParameterException rather than the TaskSetNotFoundException this
    # check is meant to exercise. Mutate a single trailing character instead so the ARN keeps
    # the same well-formed shape as the real one but refers to a task set that doesn't exist.
    bogus_task_set_arn = ts_arn[:-1] + ("0" if ts_arn[-1] != "0" else "1")
    code, message = _error(
        lambda: ecs.update_service_primary_task_set(
            cluster=cluster_arn, service=service_name, primaryTaskSet=bogus_task_set_arn
        )
    )
    assert code == "TaskSetNotFoundException", f"expected TaskSetNotFoundException, got {code}"
    bogus_task_set_id = bogus_task_set_arn.split(f"/{service_name}/", 1)[1]
    expected_message = f"Unable to find task set with id {bogus_task_set_id} on service {service_name}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the forbidden effect did not happen: the real task set is still (and only) PRIMARY
    still_all = ecs.describe_task_sets(cluster=cluster_arn, service=service_name, taskSets=[ts_arn])["taskSets"]
    assert len(still_all) == 1, f"expected exactly the one real task set, got {len(still_all)}"
    still = still_all[0]
    assert still["id"] == ts["id"], f"expected the untouched task set to still be {ts['id']!r}, got {still['id']!r}"
    assert still["status"] == "PRIMARY", (
        f"a rejected UpdateServicePrimaryTaskSet against a nonexistent task set must not disturb "
        f"the existing PRIMARY designation, got status={still['status']!r}"
    )


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


def _delete_cluster_when_settled(ecs, cluster_arn, timeout_s=120, interval_s=5):
    # DeleteCluster refuses with UpdateInProgressException while the capacity-provider
    # attachment update is still running; retry only that refusal, within a bound.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            _drain_and_delete_ecs_cluster(ecs, cluster_arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "UpdateInProgressException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
