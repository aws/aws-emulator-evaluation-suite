"""list-services-by-namespace-filters-correctly."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-services-by-namespace-filters-correctly"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListServicesByNamespace returns the Service-Connect-enabled service registered under a
    Cloud Map namespace, and excludes a plain service in the same cluster that has no Service
    Connect namespace association."""
    ecs = ctx.client("ecs")
    sd = ctx.client("servicediscovery")
    net = _default_network(ctx)

    # Kick off the namespace creation as the very first call so the async Cloud Map operation has
    # the most time to complete while the namespace-independent setup below (cluster/task-defs/
    # plain-service) runs.
    ns_name = ctx.unique_name("sim2real-behav-ns-").replace("_", "-") + ".local"
    op_id = sd.create_private_dns_namespace(
        Name=ns_name, Vpc=net["vpc_id"], Tags=[{"Key": "sim2real", "Value": "true"}]
    )["OperationId"]

    cluster_name = ctx.unique_name("sim2real-behav-ns-cluster-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_arn))

    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": net["subnet_ids"],
            "securityGroups": [net["security_group_id"]] if net["security_group_id"] else [],
            "assignPublicIp": "ENABLED",
        }
    }

    # Plain (non-Service-Connect) service — it has no namespace dependency, so do it here while the
    # namespace above is propagating, concurrently with the namespace-propagation-bound retry
    # further down.
    plain_family = ctx.unique_name("sim2real-behav-ns-plain-task-")
    plain_task_def = _register_sleep_task_def(ctx, plain_family)
    ctx.on_cleanup(
        lambda: _retire_task_definition(ecs, plain_task_def)
    )
    plain_service_name = ctx.unique_name("sim2real-behav-ns-plain-svc-")
    ecs.create_service(
        cluster=cluster_arn,
        serviceName=plain_service_name,
        taskDefinition=plain_task_def,
        desiredCount=0,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: ecs.delete_service(cluster=cluster_arn, service=plain_service_name, force=True)
        )
    )
    plain_service_arn = ecs.describe_services(cluster=cluster_arn, services=[plain_service_name])[
        "services"
    ][0]["serviceArn"]

    # Cloud Map assigns the namespace ID as soon as the operation is accepted, well before the
    # namespace itself is resolvable — GetNamespace on that id fails with NamespaceNotFound until the
    # create operation reaches a terminal status, so wait for that instead of just the id.
    op = _poll_until(
        lambda: sd.get_operation(OperationId=op_id)["Operation"],
        lambda o: o["Status"] in ("SUCCESS", "FAIL"),
        timeout_s=120.0,
        interval_s=3,
    )
    if op["Status"] == "FAIL":
        raise AssertionError(f"namespace creation failed: {op}")
    namespace_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _cleanup_namespace(sd, namespace_id))
    # ServiceConnectConfiguration.namespace and ListServicesByNamespace take the Cloud Map namespace
    # name or ARN, not its ID; resolve the ARN once and use it everywhere.
    namespace_arn = sd.get_namespace(Id=namespace_id)["Namespace"]["Arn"]

    sc_family = ctx.unique_name("sim2real-behav-ns-sc-task-")
    sc_task_def = _register_service_connect_task_def(ctx, sc_family)
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, sc_task_def))

    sc_service_name = ctx.unique_name("sim2real-behav-ns-sc-svc-")
    # A short retry for eventual consistency between Cloud Map namespace creation and ECS's view of it.
    _create_service_with_namespace_retry(
        ecs,
        timeout_s=60.0,
        interval_s=5.0,
        cluster=cluster_arn,
        serviceName=sc_service_name,
        taskDefinition=sc_task_def,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
        serviceConnectConfiguration={
            "enabled": True,
            "namespace": namespace_arn,
            "services": [
                {"portName": "app", "discoveryName": "sim2real-app", "clientAliases": [{"port": 80}]}
            ],
        },
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: ecs.delete_service(cluster=cluster_arn, service=sc_service_name, force=True)
        )
    )
    sc_service_arn = ecs.describe_services(cluster=cluster_arn, services=[sc_service_name])["services"][
        0
    ]["serviceArn"]

    namespaced = _poll_until(
        lambda: ecs.list_services_by_namespace(namespace=namespace_arn)["serviceArns"],
        lambda arns: sc_service_arn in arns,
        timeout_s=60.0,
        interval_s=5,
    )
    assert sc_service_arn in namespaced
    assert plain_service_arn not in namespaced, (
        f"a service without Service Connect namespace association leaked into "
        f"ListServicesByNamespace: {plain_service_arn}"
    )


# ===== helpers =====
def _ignore_client_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _create_service_with_namespace_retry(ecs, timeout_s=120.0, interval_s=5.0, **kwargs):
    # A freshly created Cloud Map namespace can report SUCCESS on its creation
    # operation before it's actually resolvable by ECS's CreateService namespace
    # lookup, which briefly raises NamespaceNotFoundException. Retry through that
    # propagation window instead of failing immediately.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ecs.create_service(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NamespaceNotFoundException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _cleanup_namespace(sd, namespace_id, timeout_s=120.0):
    """Delete the namespace, retrying while its services are still being released; a namespace
    that is already gone is done, any other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sd.delete_namespace(Id=namespace_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NamespaceNotFound":
                return
            if code in ("ResourceInUse", "ResourceInUseException") and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
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
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return {
        "vpc_id": vpc_id,
        "subnet_ids": [s["SubnetId"] for s in subnets[:2]],
        "security_group_id": sg_id,
    }


def _register_sleep_task_def(ctx, family):
    ecs = ctx.client("ecs")
    return ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "command": ["sleep", "1800"],
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]["taskDefinitionArn"]


def _register_service_connect_task_def(ctx, family):
    ecs = ctx.client("ecs")
    return ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "command": ["sleep", "1800"],
                "essential": True,
                "portMappings": [{"containerPort": 80, "protocol": "tcp", "name": "app"}],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]["taskDefinitionArn"]



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
