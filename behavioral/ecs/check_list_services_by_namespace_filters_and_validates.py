"""list-services-by-namespace-filters-and-validates."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-services-by-namespace-filters-and-validates"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListServicesByNamespace lists a Service Connect service under its Cloud Map namespace,
    raises NamespaceNotFoundException for a never-created namespace (not an empty list), and
    InvalidParameterException for a malformed namespace string."""
    ecs = ctx.client("ecs")
    sd = ctx.client("servicediscovery")

    namespace_name = ctx.unique_name("sim2realecsns")
    op_id = sd.create_http_namespace(Name=namespace_name)["OperationId"]

    def _op_probe():
        return sd.get_operation(OperationId=op_id)["Operation"]

    op = _poll_until(_op_probe, lambda o: o["Status"] in ("SUCCESS", "FAIL"), timeout_s=120.0, interval_s=3.0)
    assert op["Status"] == "SUCCESS", f"namespace creation failed: {op}"
    namespace_id = op["Targets"]["NAMESPACE"]

    def _delete_namespace():
        # ECS removes the Service Connect service from the namespace after the ECS service drains.
        deadline = time.monotonic() + 180.0
        while True:
            try:
                return sd.delete_namespace(Id=namespace_id)["OperationId"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceInUse" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    def _cleanup_namespace():
        try:
            del_op_id = _delete_namespace()
            _poll_until(
                lambda: sd.get_operation(OperationId=del_op_id)["Operation"],
                lambda o: o["Status"] in ("SUCCESS", "FAIL"),
                timeout_s=60.0,
                interval_s=3.0,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NamespaceNotFound", "OperationNotFound"):
                raise

    ctx.on_cleanup(_cleanup_namespace)

    subnet_id, sg_id = _default_networking(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-svcns-cl-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    family = ctx.unique_name("sim2real-ecs-svcns-td-")
    ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "web",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sleep", "60"],
                "portMappings": [{"name": "web", "containerPort": 80, "protocol": "tcp"}],
            }
        ],
    )
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, f"{family}:1"))

    service_name = ctx.unique_name("sim2real-ecs-svcns-svc-")
    created = ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=family,
        desiredCount=0,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [subnet_id],
                "securityGroups": [sg_id],
                "assignPublicIp": "ENABLED",
            }
        },
        serviceConnectConfiguration={
            "enabled": True,
            "namespace": namespace_name,
            "services": [{"portName": "web", "clientAliases": [{"port": 80}]}],
        },
    )
    service_arn = created["service"]["serviceArn"]
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True))

    # positive control: the service using this namespace for Service Connect shows up under it,
    # via an independent read (ListServicesByNamespace) distinct from the CreateService that made it
    def _list_probe():
        return ecs.list_services_by_namespace(namespace=namespace_name).get("serviceArns", [])

    arns = _poll_until(_list_probe, lambda a: service_arn in a, timeout_s=90.0, interval_s=5.0)
    assert service_arn in arns, f"expected {service_arn!r} in ListServicesByNamespace({namespace_name!r}), got {arns!r}"

    # negative: a well-formed namespace name that was never created is a NamespaceNotFoundException,
    # not an empty list indistinguishable from "no services yet"
    other_namespace = ctx.unique_name("sim2realecsns-absent")
    not_found = _error(lambda: ecs.list_services_by_namespace(namespace=other_namespace))
    expected = ("NamespaceNotFoundException", f"Failed to retrieve namespace for {other_namespace}")
    assert not_found == expected, f"expected {expected!r} for a nonexistent namespace, got {not_found!r}"

    # negative: a malformed namespace string is rejected outright, distinct from not-found
    malformed_namespace = "bad namespace !! /"
    invalid = _error(lambda: ecs.list_services_by_namespace(namespace=malformed_namespace))
    expected = (
        "InvalidParameterException",
        f'Namespace ({malformed_namespace}) must match ^[!-~&&[^<>/"]]{{1,1024}}$.',
    )
    assert invalid == expected, f"expected {expected!r} for a malformed namespace, got {invalid!r}"




def _default_networking(ctx):

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region for Fargate networking")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return subnet_id, sgs[0]["GroupId"]


def _poll_until(probe, predicate, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")



def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services or tasks remain, and a running task's ENI blocks
    deleting the network.
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
