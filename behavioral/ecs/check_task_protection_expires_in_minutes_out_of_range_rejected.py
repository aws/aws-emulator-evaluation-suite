"""task-protection-expires-in-minutes-out-of-range-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "task-protection-expires-in-minutes-out-of-range-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ecs"]

_SIM2REAL_TAGS = [
    {"key": "sim2real:managed", "value": "true"},
    {"key": "sim2real:prefix", "value": "sim2real-behav"},
]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTaskProtection rejects an expiresInMinutes value outside the documented
    [1, 2880] range instead of silently clamping it or accepting it, and does not
    change the task's existing (unprotected) state."""
    ecs = ctx.client("ecs")
    net = _own_network(ctx)

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name, tags=_SIM2REAL_TAGS)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_empty(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-behav-td-")
    task_def_arn = _register_fargate_task_def(ctx, family, command=["sleep", "300"])

    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": net["subnet_ids"],
            "securityGroups": [net["sg_id"]],
            "assignPublicIp": "ENABLED",
        }
    }
    service_name = ctx.unique_name("sim2real-behav-svc-")
    service_arn = ecs.create_service(
        cluster=cluster_arn, serviceName=service_name, taskDefinition=task_def_arn,
        desiredCount=1, launchType="FARGATE", networkConfiguration=net_cfg, tags=_SIM2REAL_TAGS,
    )["service"]["serviceArn"]

    def _drain_and_delete() -> None:
        ecs.update_service(cluster=cluster_arn, service=service_arn, desiredCount=0)
        ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True)
        # Fargate tasks stop asynchronously; wait for them before the cluster-delete
        # cleanup (below, LIFO-later) runs, or it meets a cluster that still has tasks.
        _poll_until(
            lambda: _unstopped_tasks(ecs, cluster_arn),
            lambda live: not live,
            timeout_s=240.0,
            interval_s=5.0,
        )

    ctx.on_cleanup(_drain_and_delete)

    task_arns = _poll_until(
        lambda: ecs.list_tasks(cluster=cluster_arn, serviceName=service_arn)["taskArns"],
        lambda arns: len(arns) >= 1,
        timeout_s=90.0,
        interval_s=3.0,
    )
    task_arn = task_arns[0]
    _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0],
        lambda t: t["lastStatus"] == "RUNNING",
        timeout_s=180.0,
        interval_s=5.0,
    )

    # Positive control: an in-range value must be accepted. Without this, the two
    # rejections below cannot distinguish "the documented range is enforced" from
    # "UpdateTaskProtection rejects everything on this task".
    control_resp = ecs.update_task_protection(
        cluster=cluster_arn, tasks=[task_arn], protectionEnabled=True, expiresInMinutes=60
    )
    control_protected = control_resp["protectedTasks"][0]
    assert control_protected["protectionEnabled"] is True, (
        f"positive control failed: expiresInMinutes=60 (in-range) should be accepted, got {control_resp!r}"
    )

    # Restore to unprotected before probing the invalid values, so the terminal read below
    # proves the rejections themselves left no protection, not that the control call did.
    ecs.update_task_protection(cluster=cluster_arn, tasks=[task_arn], protectionEnabled=False)

    expected_messages = {
        0: "expiresInMinutes must be at least 1",
        2881: "expiresInMinutes must be at most 2880",
    }
    for bad_value, expected_message in expected_messages.items():
        code, message = _error(
            lambda v=bad_value: ecs.update_task_protection(
                cluster=cluster_arn, tasks=[task_arn], protectionEnabled=True, expiresInMinutes=v
            )
        )
        assert code == "InvalidParameterException", (
            f"expiresInMinutes={bad_value} should be rejected with InvalidParameterException, got {code!r}"
        )
        assert message == expected_message, (
            f"expiresInMinutes={bad_value}: expected message {expected_message!r}, got {message!r}"
        )

    # The rejected calls must not have left the task protected.
    still_unprotected = ecs.get_task_protection(cluster=cluster_arn, tasks=[task_arn])["protectedTasks"][0]
    assert still_unprotected["protectionEnabled"] is False, (
        f"task became protected despite out-of-range expiresInMinutes being rejected: {still_unprotected}"
    )


# ===== helpers =====

def _error(fn) -> tuple[str, str]:
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _unstopped_tasks(ecs, cluster_arn: str) -> list[str]:
    arns = ecs.list_tasks(cluster=cluster_arn, desiredStatus="RUNNING")["taskArns"]
    arns += ecs.list_tasks(cluster=cluster_arn, desiredStatus="STOPPED")["taskArns"]
    if not arns:
        return []
    tasks = ecs.describe_tasks(cluster=cluster_arn, tasks=arns)["tasks"]
    return [t["taskArn"] for t in tasks if t["lastStatus"] != "STOPPED"]


def _delete_cluster_when_empty(ecs, cluster_arn: str, *, timeout_s: float = 120.0, interval_s: float = 2.0) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code not in (
                "ClusterContainsServicesException",
                "ClusterContainsTasksException",
                "ClusterContainsContainerInstancesException",
                "UpdateInProgressException",
            ) or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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


def _register_fargate_task_def(ctx, family: str, command: list[str] | None = None) -> str:
    ecs = ctx.client("ecs")
    container: dict[str, Any] = {
        "name": "app",
        "image": "public.ecr.aws/docker/library/alpine:3.20",
        "essential": True,
    }
    if command:
        container["command"] = command
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[container],
        tags=_SIM2REAL_TAGS,
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


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
