"""runtask-without-capacity-rejected."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "runtask-without-capacity-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]

_ECS_TAGS = [{"key": "sim2real", "value": "true"}]
_EC2_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav-ecs-nocap"},
]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EC2-launch RunTask succeeds with an agent-registered container instance, fails with
    InvalidParameterException and creates no task once that capacity is force-deregistered, and
    succeeds again when fresh capacity registers: the refusal tracks capacity."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    cluster = _create_cluster(ctx, ecs)
    cluster_arn = cluster["clusterArn"]
    cluster_name = cluster["clusterName"]
    td = _register_task_def(ctx, ecs)

    def _run_task():
        return ecs.run_task(
            cluster=cluster_arn,
            taskDefinition=td["taskDefinitionArn"],
            launchType="EC2",
            count=1,
        )

    def _active_instances():
        return ecs.list_container_instances(cluster=cluster_arn, status="ACTIVE")["containerInstanceArns"]

    def _stop_and_wait(task_arn):
        ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="check cleanup")
        _poll_until(
            lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]["lastStatus"],
            lambda s: s == "STOPPED",
            timeout_s=180.0,
            interval_s=5.0,
        )

    subnet_id, sg_id = _dedicated_network(ctx, ec2)
    profile_name = _ensure_ecs_instance_profile(ctx, iam)
    ami_id = _ecs_optimized_ami(ssm)

    # ---- Positive control: real capacity present, RunTask succeeds. ----
    instance_id_1 = _launch_agent_instance(ctx, ec2, cluster_name, subnet_id, sg_id, profile_name, ami_id)
    _poll_until(_active_instances, lambda arns: len(arns) >= 1, timeout_s=480.0, interval_s=15.0)

    positive = _retry_throttled(_run_task)
    assert not positive.get("failures"), (
        f"positive control: RunTask failed even with real capacity present: {positive.get('failures')}"
    )
    task_arn_1 = positive["tasks"][0]["taskArn"]
    _stop_and_wait(task_arn_1)

    # ---- Break: deterministically strip the cluster of all capacity. ----
    ci_arn_1 = _active_instances()[0]
    ecs.deregister_container_instance(cluster=cluster_arn, containerInstance=ci_arn_1, force=True)
    assert _active_instances() == [], "container instance still ACTIVE after forced deregistration"
    _tolerate_gone(lambda: ec2.terminate_instances(InstanceIds=[instance_id_1]), "InvalidInstanceID.NotFound")

    code, message = _expect_error(_run_task, "InvalidParameterException")
    assert code == "InvalidParameterException", f"expected InvalidParameterException with zero capacity, got {code}"
    assert message == "No Container Instances were found in your cluster.", f"unexpected error message with zero capacity: {message!r}"

    # No phantom task may have been created by the refused call.
    assert ecs.list_tasks(cluster=cluster_arn)["taskArns"] == [], "a task was created despite zero capacity"

    # ---- Restore: fresh capacity makes the identical call succeed again. ----
    instance_id_2 = _launch_agent_instance(ctx, ec2, cluster_name, subnet_id, sg_id, profile_name, ami_id)
    _poll_until(_active_instances, lambda arns: len(arns) >= 1, timeout_s=480.0, interval_s=15.0)
    ci_arn_2 = _active_instances()[0]
    ctx.on_cleanup(
        lambda: _tolerate_gone(
            lambda: ecs.deregister_container_instance(cluster=cluster_arn, containerInstance=ci_arn_2, force=True),
            "ClusterNotFoundException",
        )
    )

    restored = _retry_throttled(_run_task)
    assert not restored.get("failures"), (
        f"restore: RunTask failed even after capacity was re-registered: {restored.get('failures')}"
    )
    task_arn_2 = restored["tasks"][0]["taskArn"]
    _stop_and_wait(task_arn_2)


# ===== helpers =====

_DEFAULT_CONTAINER_DEFS = [
    {
        "name": "app",
        # Public ECR mirror: pullable without Docker Hub credentials/rate limits.
        "image": "public.ecr.aws/docker/library/busybox:stable",
        "cpu": 64,
        "memory": 128,
        "essential": True,
        "command": ["sh", "-c", "sleep 3600"],
    }
]

# Codes that mean "the control plane is busy", never "your request was wrong".
_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "RequestLimitExceeded",
    "TooManyRequestsException",
)


def _error(fn):
    """Return (code, message) of the ClientError *fn* raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"operation unexpectedly SUCCEEDED and returned {result!r}")


def _expect_error(fn, allowed, attempts: int = 7):
    """Return (code, message) raised by *fn*, retrying through throttles."""
    for i in range(attempts):
        code, message = _error(fn)
        if code not in _THROTTLE_CODES:
            return code, message
        time.sleep(min(2.0 * (2**i), 20.0))
    raise AssertionError(f"still throttled after {attempts} attempts; expected {allowed}")


def _retry_throttled(fn, attempts: int = 7, base_delay: float = 2.0):
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(min(base_delay * (2**i), 20.0))
    raise last


def _tolerate_gone(fn, *gone) -> None:
    """Run a teardown call: an already-gone resource (an error code in *gone*) is fine; any other
    failure raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in gone:
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_cluster(ctx, ecs, name=None, **kwargs) -> dict:
    name = name or ctx.unique_name("sim2real-behav-ecs-cluster-")
    resp = _retry_throttled(lambda: ecs.create_cluster(clusterName=name, tags=_ECS_TAGS, **kwargs))
    arn = resp["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_retry(ecs, arn))
    return resp["cluster"]


def _delete_cluster_retry(ecs, cluster_arn, timeout_s: float = 180.0) -> None:
    """DeleteCluster races the eventual-consistency window between a synchronous
    DeregisterContainerInstance/StopTask and the cluster's own aggregate counters, so a
    delete issued immediately after can bounce off ClusterContainsContainerInstancesException
    or ClusterContainsTasksException even though the underlying resources are already gone.
    Retry through that window, then raise."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ClusterNotFoundException":
                return
            if code not in ("ClusterContainsContainerInstancesException", "ClusterContainsTasksException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _register_task_def(ctx, ecs, family=None, container_defs=None, **kwargs) -> dict:
    """Register an EC2/bridge task definition.

    bridge networking is used deliberately: awsvpc requires real subnet IDs.
    """
    family = family or ctx.unique_name("sim2real-behav-ecs-taskdef-")
    resp = _retry_throttled(
        lambda: ecs.register_task_definition(
            family=family,
            containerDefinitions=container_defs or _DEFAULT_CONTAINER_DEFS,
            requiresCompatibilities=kwargs.pop("requiresCompatibilities", ["EC2"]),
            networkMode=kwargs.pop("networkMode", "bridge"),
            tags=_ECS_TAGS,
            **kwargs,
        )
    )
    td = resp["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td_arn))
    return td


def _dedicated_network(ctx, ec2):
    """Provision a small dedicated VPC (public subnet, IGW, default route) for the
    capacity-source EC2 instances, so the check does not depend on a default VPC."""
    vpc_id = ec2.create_vpc(
        CidrBlock="10.199.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _EC2_TAGS}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.199.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _EC2_TAGS}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _EC2_TAGS}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
            "SecurityGroups"
        ]
        if sg["GroupName"] == "default"
    )

    def _teardown_network():
        # ENIs from the just-terminated EC2 instances linger briefly; wait them out on their
        # own budget, then give each delete a separate budget for DependencyViolation retries.
        eni_deadline = time.monotonic() + 300
        while time.monotonic() < eni_deadline:
            enis = ec2.describe_network_interfaces(
                Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
            ).get("NetworkInterfaces", [])
            if not enis:
                break
            time.sleep(2)

        def _delete(call, *gone):
            deadline = time.monotonic() + 90
            while True:
                try:
                    return _tolerate_gone(call, *gone)
                except ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") != "DependencyViolation":
                        raise
                    if time.monotonic() >= deadline:
                        raise
                time.sleep(2)

        _delete(lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound")
        _delete(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id),
                "Gateway.NotAttached", "InvalidInternetGatewayID.NotFound")
        _delete(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id), "InvalidInternetGatewayID.NotFound")
        _delete(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound")

    ctx.on_cleanup(_teardown_network)
    return subnet_id, sg_id


def _ensure_ecs_instance_profile(ctx, iam) -> str:
    """Create a throwaway ecsInstanceRole-equivalent role + instance profile for the EC2
    instances that will self-register as ECS container instances."""
    role_name = ctx.unique_name("sim2real-ecs-nocap-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy, Tags=_EC2_TAGS)
    ctx.on_cleanup(lambda: _tolerate_gone(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: _tolerate_gone(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn), "NoSuchEntity")
    )

    profile_name = role_name
    iam.create_instance_profile(InstanceProfileName=profile_name, Tags=_EC2_TAGS)
    ctx.on_cleanup(
        lambda: _tolerate_gone(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name), "NoSuchEntity")
    )

    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _tolerate_gone(
            lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name),
            "NoSuchEntity",
        )
    )

    # IAM/instance-profile propagation lag before EC2 will accept it as a launch parameter.
    _poll_until(
        lambda: iam.get_instance_profile(InstanceProfileName=profile_name),
        lambda resp: bool(resp["InstanceProfile"]["Roles"]),
        timeout_s=60.0,
        interval_s=3.0,
    )
    return profile_name


def _ecs_optimized_ami(ssm) -> str:
    resp = ssm.get_parameter(Name="/aws/service/ecs/optimized-ami/amazon-linux-2/recommended")
    return json.loads(resp["Parameter"]["Value"])["image_id"]


def _launch_agent_instance(ctx, ec2, cluster_name, subnet_id, sg_id, profile_name, ami_id) -> str:
    """Launch a real EC2 instance whose ECS agent self-registers with *cluster_name*."""
    user_data = base64.b64encode(f"#!/bin/bash\necho ECS_CLUSTER={cluster_name} >> /etc/ecs/ecs.config\n".encode()).decode()
    instance_id = None
    last_err = None
    for _attempt in range(3):
        try:
            reservation = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                SecurityGroupIds=[sg_id],
                IamInstanceProfile={"Name": profile_name},
                UserData=user_data,
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": _EC2_TAGS + [{"Key": "Name", "Value": ctx.unique_name("sim2real-ecs-nocap-")}],
                    }
                ],
            )
            instance_id = reservation["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            last_err = exc
            time.sleep(5.0)
    if instance_id is None:
        raise AssertionError(f"could not launch a capacity-source EC2 instance: {last_err}")
    ctx.on_cleanup(
        lambda: _tolerate_gone(lambda: ec2.terminate_instances(InstanceIds=[instance_id]), "InvalidInstanceID.NotFound")
    )
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
