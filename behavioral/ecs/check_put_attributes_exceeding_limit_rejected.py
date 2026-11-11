"""put-attributes-exceeding-limit-rejected."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-attributes-exceeding-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An attribute beyond the 10-per-resource limit is rejected (AttributeLimitExceededException)
    and not applied; after freeing one slot the identical call succeeds."""
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx, ecs)
    cluster_name = cluster["clusterName"]
    ci = _launch_real_container_instance(ctx, ecs, cluster_name)
    ci_id = ci["containerInstanceArn"]

    # PutAttributes accepts at most 10 attributes per call; fill the
    # documented per-resource ceiling of 10 in a single call.
    first_batch = [{"name": f"attr-{i}", "targetId": ci_id, "value": "v"} for i in range(10)]
    ecs.put_attributes(cluster=cluster_name, attributes=first_batch)

    code, message = _error(
        lambda: ecs.put_attributes(
            cluster=cluster_name,
            attributes=[{"name": "one-too-many", "targetId": ci_id, "value": "v"}],
        )
    )
    assert code == "AttributeLimitExceededException", (
        f"expected AttributeLimitExceededException beyond the 10-attribute-per-resource limit, got {code}"
    )
    assert message == "Attribute per target limit exceeded.", f"unexpected message: {message!r}"

    listed = ecs.list_attributes(cluster=cluster_name, targetType="container-instance")["attributes"]
    # ListAttributes also returns ECS-managed built-in attributes for the
    # same targetId (ecs.ami-id, ecs.availability-zone, ...); scope down to
    # OUR custom attributes to check the 10-per-resource ceiling specifically.
    names = {
        a["name"]
        for a in listed
        if a.get("targetId") == ci_id and a["name"].startswith(("attr-", "one-too-many"))
    }
    assert "one-too-many" not in names, "the rejected attribute must not have been applied"
    assert len(names) == 10, f"expected exactly 10 custom attributes to remain on the resource, got {len(names)}"

    # Free exactly one slot: the identical call must now succeed.
    ecs.delete_attributes(cluster=cluster_name, attributes=[{"name": "attr-0", "targetId": ci_id}])
    try:
        ecs.put_attributes(
            cluster=cluster_name,
            attributes=[{"name": "one-too-many", "targetId": ci_id, "value": "v"}],
        )
    except ClientError as exc:
        raise AssertionError(
            "expected the identical PutAttributes('one-too-many') call to succeed once a slot "
            f"was freed, got {exc.response.get('Error', {}).get('Code')}"
        ) from exc

    # ListAttributes lags PutAttributes/DeleteAttributes briefly, so poll for the new attribute.
    def _list_custom_names():
        listed = ecs.list_attributes(cluster=cluster_name, targetType="container-instance")["attributes"]
        return {
            a["name"]
            for a in listed
            if a.get("targetId") == ci_id and a["name"].startswith(("attr-", "one-too-many"))
        }

    restored_names = _poll_until(
        _list_custom_names,
        lambda names: "one-too-many" in names,
        timeout_s=30.0,
        interval_s=3.0,
        description="ListAttributes to reflect the restored PutAttributes('one-too-many') call",
    )
    assert "attr-0" not in restored_names, f"expected the deleted attr-0 to be gone, got {restored_names}"
    assert len(restored_names) == 10, (
        f"expected exactly 10 custom attributes after freeing one and re-adding one, got {restored_names}"
    )



_ECS_INSTANCE_MANAGED_POLICY = (
    "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
)


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "InvalidInstanceID.NotFound",
            "NoSuchEntity",
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _create_cluster(ctx, ecs, name=None, **kwargs) -> dict:
    name = name or ctx.unique_name("sim2real-behav-ecs-cluster-")
    resp = ecs.create_cluster(clusterName=name, **kwargs)
    ctx.on_cleanup(lambda: _best_effort(lambda: ecs.delete_cluster(cluster=name)))
    return resp["cluster"]


_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _public_network(ctx):
    """(subnet, security group) in a VPC this check creates, with an internet route so the
    container instance's ECS agent reaches the ECS endpoint. One cleanup tears it down
    after the instance's ENI is released."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.196.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.196.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _NET_TAGS}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"][0][
        "RouteTableId"
    ]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
        if sg["GroupName"] == "default"
    )

    def _teardown_network():
        deadline = time.monotonic() + 240
        while True:
            try:
                ec2.delete_subnet(SubnetId=subnet_id)
                break
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
                time.sleep(10)
        ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        ec2.delete_internet_gateway(InternetGatewayId=igw_id)
        ec2.delete_vpc(VpcId=vpc_id)

    ctx.on_cleanup(_teardown_network)
    return subnet_id, sg_id


def _create_instance_role_with_profile(ctx, iam, name_prefix: str, trust_service: str,
                                       managed_policy_arns=()) -> str:
    """Create an IAM role + same-named instance profile, tracked for teardown.

    Returns the instance-profile ARN.
    """
    role_name = ctx.unique_name(name_prefix)[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))
    for arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
        ctx.on_cleanup(
            lambda a=arn: _best_effort(
                lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=a)
            )
        )

    iam.create_instance_profile(InstanceProfileName=role_name)
    ctx.on_cleanup(
        lambda: _best_effort(lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    )
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: iam.remove_role_from_instance_profile(
                InstanceProfileName=role_name, RoleName=role_name
            )
        )
    )
    return iam.get_instance_profile(InstanceProfileName=role_name)["InstanceProfile"]["Arn"]


def _launch_real_container_instance(ctx, ecs, cluster: str, *, timeout_s: float = 200) -> dict:
    """Launch a t3.micro whose ECS agent self-registers it (RegisterContainerInstance needs an
    AWS-signed identity document) and return its ContainerInstance description."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    subnet_id, sg = _public_network(ctx)
    ami_id = ssm.get_parameter(
        Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
    )["Parameter"]["Value"]

    profile_arn = _create_instance_role_with_profile(
        ctx,
        iam,
        "sim2real-behav-ecsInstanceRole-",
        "ec2.amazonaws.com",
        managed_policy_arns=[_ECS_INSTANCE_MANAGED_POLICY],
    )

    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster} >> /etc/ecs/ecs.config\n"
    encoded_user_data = base64.b64encode(user_data.encode()).decode()

    last_exc: Exception | None = None
    instance_id: str | None = None
    left = ctx.time_left()
    launch_deadline = time.monotonic() + (40.0 if left is None else min(40.0, left))
    while instance_id is None and time.monotonic() < launch_deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Arn": profile_arn},
                SubnetId=subnet_id,
                SecurityGroupIds=[sg],
                UserData=encoded_user_data,
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [
                            {
                                "Key": "Name",
                                "Value": ctx.unique_name("sim2real-behav-ecs-ci-"),
                            }
                        ],
                    }
                ],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except Exception as exc:  # noqa: BLE001 - IAM propagation lag surfaces as a ClientError
            last_exc = exc
            time.sleep(2)
    if instance_id is None:
        raise last_exc or RuntimeError("failed to launch container-instance EC2 host")
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))

    def _find():
        arns = ecs.list_container_instances(cluster=cluster).get("containerInstanceArns", [])
        if not arns:
            return None
        described = ecs.describe_container_instances(cluster=cluster, containerInstances=arns)[
            "containerInstances"
        ]
        for ci in described:
            if ci.get("ec2InstanceId") == instance_id:
                return ci
        return None

    ci = _poll_until(
        _find,
        lambda x: x is not None,
        timeout_s=timeout_s,
        interval_s=10,
        description="EC2 instance registers as an ECS container instance",
    )
    ci_arn = ci["containerInstanceArn"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: ecs.deregister_container_instance(
                cluster=cluster, containerInstance=ci_arn, force=True
            )
        )
    )
    return ci


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
