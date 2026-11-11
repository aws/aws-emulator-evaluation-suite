"""update-inactive-service-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-inactive-service-rejected"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateService on a service that has been deleted (and is now INACTIVE) is rejected
    with ServiceNotActiveException, doesn't change the service's desiredCount, and a
    positive control update on a live ACTIVE service in the same cluster still succeeds."""
    ecs = ctx.client("ecs")
    net = _own_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": net["subnet_ids"][:1],
            "securityGroups": [net["sg_id"]],
            "assignPublicIp": "ENABLED",
        }
    }
    _ensure_ecs_slr(ctx)

    cluster = ctx.unique_name("sim2real-behav-ecs-inactive-svc-cluster-")
    _retry_slr(lambda: ecs.create_cluster(clusterName=cluster))
    ctx.on_cleanup(lambda: _delete_cluster_retry(ecs, cluster))

    family = ctx.unique_name("sim2real-behav-ecs-inactive-svc-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "command": ["sleep", "60"],
                "essential": True,
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    target_name = ctx.unique_name("sim2real-behav-ecs-inactive-svc-target-")
    control_name = ctx.unique_name("sim2real-behav-ecs-inactive-svc-control-")

    _retry_slr(lambda: ecs.create_service(
        cluster=cluster,
        serviceName=target_name,
        taskDefinition=td_arn,
        desiredCount=0,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
    ))
    _retry_slr(lambda: ecs.create_service(
        cluster=cluster,
        serviceName=control_name,
        taskDefinition=td_arn,
        desiredCount=0,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
    ))

    def _cleanup_control() -> None:
        ecs.update_service(cluster=cluster, service=control_name, desiredCount=0)
        _poll_until(
            lambda: ecs.describe_services(cluster=cluster, services=[control_name])["services"][0]["runningCount"],
            lambda n: n == 0,
            timeout_s=180,
            interval_s=5,
        )
        ecs.delete_service(cluster=cluster, service=control_name, force=True)

    ctx.on_cleanup(_cleanup_control)

    # Drain and delete the target service so it moves to INACTIVE.
    ecs.delete_service(cluster=cluster, service=target_name, force=True)
    _poll_until(
        lambda: ecs.describe_services(cluster=cluster, services=[target_name])["services"][0]["status"],
        lambda s: s == "INACTIVE",
        timeout_s=120,
        interval_s=5,
    )

    code, message = _error(lambda: ecs.update_service(cluster=cluster, service=target_name, desiredCount=5))
    assert code == "ServiceNotActiveException", f"expected ServiceNotActiveException, got {code}"
    expected_message = "Service was not ACTIVE."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the inactive service's desiredCount/status did not change.
    svc = ecs.describe_services(cluster=cluster, services=[target_name])["services"][0]
    assert svc["desiredCount"] == 0, f"expected desiredCount unchanged at 0, got {svc['desiredCount']}"
    assert svc["status"] == "INACTIVE", f"expected status to remain INACTIVE, got {svc['status']}"

    # Positive control: the identical style of update on a live ACTIVE service succeeds.
    ecs.update_service(cluster=cluster, service=control_name, desiredCount=1)
    control_desired = _poll_until(
        lambda: ecs.describe_services(cluster=cluster, services=[control_name])["services"][0]["desiredCount"],
        lambda n: n == 1,
        timeout_s=60,
        interval_s=5,
    )
    assert control_desired == 1, f"expected the control service's desiredCount to reach 1, got {control_desired}"


def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ensure_ecs_slr(ctx) -> None:
    """Make sure AWSServiceRoleForECS exists so CreateService/CreateCluster don't hit
    'Unable to assume the service linked role' on a fresh account. Propagation of a
    freshly-created role is handled by `_retry_slr` on the calls that need it, not by
    a blind sleep here."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("InvalidInput",):
            raise


def _retry_slr(fn, timeout_s=90.0, interval_s=5.0):
    """Retry an ECS call that can transiently fail with
    'Unable to assume the service linked role' right after account/role creation."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            msg = str(e)
            if "Unable to assume the service linked role" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _own_network(ctx):
    """Create a dedicated VPC with one public subnet (internet gateway + default route,
    so a Fargate task can pull a public-ECR image) and return
    {"vpc_id", "subnet_ids", "sg_id"} using that VPC's own default security group.

    One cleanup tears the stack down; it is registered before any ECS resource, so it
    runs last and first waits out the Fargate ENIs that linger after tasks stop."""
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.198.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    state = {"subnet_id": None, "igw_id": None}

    def _teardown_network():
        deadline = time.monotonic() + 540
        subnet_id, igw_id = state["subnet_id"], state["igw_id"]
        if subnet_id:
            while time.monotonic() < deadline:
                enis = ec2.describe_network_interfaces(
                    Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
                ).get("NetworkInterfaces", [])
                if not enis:
                    break
                time.sleep(10)
            while True:
                try:
                    ec2.delete_subnet(SubnetId=subnet_id)
                    break
                except ClientError as exc:
                    if exc.response["Error"]["Code"] == "InvalidSubnetID.NotFound":
                        break
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(10)
        if igw_id:
            ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
            ec2.delete_internet_gateway(InternetGatewayId=igw_id)
        while True:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                break
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "InvalidVpcID.NotFound":
                    break
                if time.monotonic() >= deadline:
                    raise
                time.sleep(10)

    ctx.on_cleanup(_teardown_network)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.198.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
    )["Subnet"]["SubnetId"]
    state["subnet_id"] = subnet_id
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _NET_TAGS}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    state["igw_id"] = igw_id
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"][0]["GroupId"]
    return {"vpc_id": vpc_id, "subnet_ids": [subnet_id], "sg_id": sg_id}


def _delete_cluster_retry(ecs, cluster_name, timeout_s=90.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterContainsTasksException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
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
