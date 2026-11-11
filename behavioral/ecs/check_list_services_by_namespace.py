"""list-services-by-namespace."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "list-services-by-namespace"
GROUP = 'service-lifecycle'
SERVICES = ['ecs']


def _default_vpc_id(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    return vpcs[0]["VpcId"]


def _default_subnets(ec2, *, ctx):
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no network subnets available in this account/region")
    return [s["SubnetId"] for s in subnets]


def _default_sg(ec2, *, ctx):
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group available in this account/region")
    return sgs[0]["GroupId"]


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _ignore_client_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_private_dns_namespace(ctx, *, timeout_s=120):
    ec2 = ctx.client("ec2")
    sd = ctx.client("servicediscovery")
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    ns_name = f"{ctx.unique_name('sim2real-behav-ecs-ns-')}.local"
    op_id = sd.create_private_dns_namespace(Name=ns_name, Vpc=vpc_id)["OperationId"]
    op = _poll_until(
        lambda: sd.get_operation(OperationId=op_id)["Operation"],
        lambda o: o["Status"] in ("SUCCESS", "FAIL"),
        timeout_s=timeout_s,
        interval_s=5,
        description="Cloud Map CreateNamespace operation completes",
    )
    if op["Status"] != "SUCCESS":
        raise AssertionError(f"Cloud Map namespace creation failed: {op.get('ErrorMessage')}")
    namespace_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: sd.delete_namespace(Id=namespace_id))
    return namespace_id


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Service Connect service is listed by ListServicesByNamespace for its Cloud Map namespace,
    and a missing namespace is rejected with NamespaceNotFoundException, not an empty list that
    reads the same as "no services yet"."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    sd = ctx.client("servicediscovery")
    namespace_id = _create_private_dns_namespace(ctx)
    namespace = sd.get_namespace(Id=namespace_id)["Namespace"]
    namespace_arn = namespace["Arn"]
    namespace_name = namespace["Name"]

    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, name))
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    td = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": ["sleep", "600"],
                "portMappings": [{"containerPort": 80, "protocol": "tcp", "name": "app-port"}],
            }
        ],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"]))
    subnets = _default_subnets(ec2, ctx=ctx)
    sg = _default_sg(ec2, ctx=ctx)

    svc_name = ctx.unique_name("sim2real-behav-ecs-svc-")
    svc = ecs.create_service(
        cluster=name,
        serviceName=svc_name,
        taskDefinition=td["taskDefinitionArn"],
        desiredCount=0,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets[:1],
                "securityGroups": [sg],
                "assignPublicIp": "ENABLED",
            }
        },
        serviceConnectConfiguration={
            "enabled": True,
            "namespace": namespace_arn,
            "services": [
                {
                    "portName": "app-port",
                    "discoveryName": ctx.unique_name("disc-")[:31],
                    "clientAliases": [{"port": 80}],
                }
            ],
        },
    )["service"]
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: ecs.delete_service(cluster=name, service=svc_name, force=True)))
    svc_arn = svc["serviceArn"]

    listed = _poll_until(
        lambda: ecs.list_services_by_namespace(namespace=namespace_name).get("serviceArns", []),
        lambda arns: svc_arn in arns,
        timeout_s=60,
        interval_s=3,
        description="the Service-Connect-enabled service becomes visible via ListServicesByNamespace",
    )
    assert svc_arn in listed, f"expected {svc_arn} in ListServicesByNamespace, got {listed}"

    # overly-permissive boundary: an unknown namespace must be rejected, not
    # silently return an empty list indistinguishable from "no services yet".
    missing_namespace = ctx.unique_name("no-such-namespace-") + ".local"
    error = _error(lambda: ecs.list_services_by_namespace(namespace=missing_namespace))
    expected = (
        "NamespaceNotFoundException",
        f"Failed to retrieve namespace for {missing_namespace}",
    )
    assert error == expected, f"expected {expected!r}, got {error!r}"

    # Deleting the service is a free negative here — the deleted service must drop out of
    # ListServicesByNamespace, not linger because the namespace's own view is stale.
    ecs.delete_service(cluster=name, service=svc_name, force=True)
    remaining = _poll_until(
        lambda: ecs.list_services_by_namespace(namespace=namespace_name).get("serviceArns", []),
        lambda arns: svc_arn not in arns,
        timeout_s=60,
        interval_s=3,
        description="the deleted service drops out of ListServicesByNamespace",
    )
    assert svc_arn not in remaining, (
        f"expected {svc_arn} removed from ListServicesByNamespace after delete, still present: {remaining}"
    )



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
