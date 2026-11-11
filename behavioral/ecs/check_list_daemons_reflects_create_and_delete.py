"""list-daemons-reflects-create-and-delete."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-daemons-reflects-create-and-delete"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDaemons includes a daemon immediately after CreateDaemon (scoped to its cluster)
    and excludes it once DeleteDaemon completes."""

    ecs = ctx.client("ecs")
    infra = _setup_daemon_infra(ctx)
    cluster_arn, cp_arn = infra["cluster_arn"], infra["cp_arn"]
    task_def_arn = _register_daemon_task_definition(ctx)

    daemon_name = ctx.unique_name("sim2real-daemon-")
    try:
        created = ecs.create_daemon(
            daemonName=daemon_name,
            daemonTaskDefinitionArn=task_def_arn,
            capacityProviderArns=[cp_arn],
            clusterArn=cluster_arn,
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "UnsupportedFeatureException":
            raise AssertionError(f"unreachable: CreateDaemon unsupported here: {e}")
        raise
    daemon_arn = created["daemonArn"]
    ctx.on_cleanup(lambda: _safe_delete_daemon(ecs, daemon_arn))

    def _list_arns():
        return {d["daemonArn"] for d in ecs.list_daemons(clusterArn=cluster_arn)["daemonSummariesList"]}

    listed_after_create = _poll_until(_list_arns, lambda arns: daemon_arn in arns, timeout_s=30, interval_s=2)
    assert daemon_arn in listed_after_create, (
        f"expected {daemon_arn} in ListDaemons(cluster={cluster_arn}) after CreateDaemon, "
        f"got {listed_after_create}"
    )

    _poll_until(
        lambda: ecs.describe_daemon(daemonArn=daemon_arn)["daemon"]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=180,
        interval_s=2,
    )

    ecs.delete_daemon(daemonArn=daemon_arn)

    listed_after_delete = _poll_until(_list_arns, lambda arns: daemon_arn not in arns, timeout_s=180, interval_s=2)
    assert daemon_arn not in listed_after_delete, (
        f"expected {daemon_arn} absent from ListDaemons(cluster={cluster_arn}) after DeleteDaemon, "
        f"still present in {listed_after_delete}"
    )


# ===== helpers =====
_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _own_network(ctx):
    """(subnet ids, security group id) in a VPC this check creates: two public subnets in
    distinct AZs behind an internet gateway, so a managed instance reaches the ECS endpoint.
    The teardown is registered before anything that can launch into the subnets, so it runs
    after the capacity provider and its instances are gone, and it waits out their ENIs."""
    ec2 = ctx.client("ec2")
    made: dict = {"subnets": []}

    def _teardown_network():
        from botocore.exceptions import ClientError

        deadline = time.monotonic() + 600
        for subnet_id in made["subnets"]:
            while True:
                try:
                    ec2.delete_subnet(SubnetId=subnet_id)
                    break
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                        raise
                    time.sleep(15)
        if made.get("igw"):
            ec2.detach_internet_gateway(InternetGatewayId=made["igw"], VpcId=made["vpc"])
            ec2.delete_internet_gateway(InternetGatewayId=made["igw"])
        ec2.delete_vpc(VpcId=made["vpc"])

    made["vpc"] = ec2.create_vpc(
        CidrBlock="10.198.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown_network)
    vpc_id = made["vpc"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
    ][:2]
    for i, zone in enumerate(zones):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.198.0.{i * 128}/25",
            AvailabilityZone=zone,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
        )["Subnet"]["SubnetId"]
        made["subnets"].append(subnet_id)
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    made["igw"] = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _NET_TAGS}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=made["igw"], VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"][0][
        "RouteTableId"
    ]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=made["igw"])
    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
        if sg["GroupName"] == "default"
    )
    return list(made["subnets"]), sg_id


def _delete_capacity_provider_and_wait(ecs, cp_arn):
    """DeleteCapacityProvider is asynchronous; the cluster refuses deletion while the provider is
    still attached, so wait until the provider reports INACTIVE or is gone."""
    ecs.delete_capacity_provider(capacityProvider=cp_arn)
    _poll_until(
        lambda: [c["status"] for c in ecs.describe_capacity_providers(capacityProviders=[cp_arn])["capacityProviders"]],
        lambda statuses: not statuses or statuses[0] == "INACTIVE",
        timeout_s=600,
        interval_s=10,
    )


def _delete_cluster_when_detached(ecs, cluster_arn):
    deadline = time.monotonic() + 300
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_arn)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
            time.sleep(10)


def _terminal_cp(ecs, cp_arn):
    """Poll a new capacity provider out of PROVISIONING and return its terminal description."""
    return _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_arn])["capacityProviders"][0],
        lambda d: d["status"] in ("ACTIVE", "INACTIVE"),
        timeout_s=150,
        interval_s=4,
    )


def _is_role_propagation_race(desc) -> bool:
    """ECS assumes the fresh infrastructure role cross-service; while that role is not yet visible
    the provider goes INACTIVE with a ServiceAccessDeniedException reason."""
    return "ServiceAccessDenied" in str(desc.get("updateStatusReason") or "")


def _poll_until(probe, predicate, timeout_s=120, interval_s=3):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _safe_delete_daemon(ecs, daemon_arn):
    try:
        ecs.delete_daemon(daemonArn=daemon_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "DaemonNotFoundException",
        ):
            raise


def _register_daemon_task_definition(ctx, sleep_seconds=3600):
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-daemon-td-")
    resp = ecs.register_daemon_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "agent",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "memory": 128,
                "command": ["sh", "-c", f"sleep {sleep_seconds}"],
            }
        ],
    )
    arn = resp["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: _safe_delete_daemon_td(ecs, arn))
    return arn


def _safe_delete_daemon_td(ecs, arn):
    """Delete the daemon task definition; one already gone is done, any other error raises."""
    try:
        ecs.delete_daemon_task_definition(daemonTaskDefinition=arn)
    except ClientError as exc:
        if "does not exist" not in exc.response["Error"].get("Message", ""):
            raise


def _setup_daemon_infra(ctx):

    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ecs = ctx.client("ecs")
    sts = ctx.client("sts")

    subnets, sg_id = _own_network(ctx)

    suffix = uuid.uuid4().hex[:10]
    infra_role_name = f"sim2real-ecs-infra-{suffix}"
    instance_role_name = f"ecsInstanceRole-sim2real-{suffix}"

    infra_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    instance_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )

    try:
        infra_role_arn = iam.create_role(RoleName=infra_role_name, AssumeRolePolicyDocument=infra_trust)["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=infra_role_name))
        infra_policy_arn = "arn:aws:iam::aws:policy/AmazonECSInfrastructureRolePolicyForManagedInstances"
        iam.attach_role_policy(RoleName=infra_role_name, PolicyArn=infra_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=infra_role_name, PolicyArn=infra_policy_arn))

        instance_role_arn = iam.create_role(RoleName=instance_role_name, AssumeRolePolicyDocument=instance_trust)["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=instance_role_name))
        instance_policy_arn = "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"
        iam.attach_role_policy(RoleName=instance_role_name, PolicyArn=instance_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=instance_role_name, PolicyArn=instance_policy_arn))

        iam.create_instance_profile(InstanceProfileName=instance_role_name)
        ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=instance_role_name))
        iam.add_role_to_instance_profile(InstanceProfileName=instance_role_name, RoleName=instance_role_name)
        ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=instance_role_name, RoleName=instance_role_name))

        # The infra role launches EC2 instances using the instance profile on our
        # behalf, so it needs PassRole on the instance role — the managed policy
        # alone doesn't grant it and ECS reports the gap as CREATE_FAILED /
        # ServiceAccessDeniedException on the capacity provider, not on this call.
        pass_role_policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": instance_role_arn}],
            }
        )
        iam.put_role_policy(RoleName=infra_role_name, PolicyName="pass-instance-role", PolicyDocument=pass_role_policy)
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=infra_role_name, PolicyName="pass-instance-role"))
    except ClientError as e:
        raise AssertionError(f"unreachable: cannot provision IAM roles for ECS Managed Instances: {e}")

    account_id = sts.get_caller_identity()["Account"]
    profile_arn = f"arn:aws:iam::{account_id}:instance-profile/{instance_role_name}"

    cluster_name = ctx.unique_name("sim2real-ecs-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_detached(ecs, cluster_arn))

    cp_arn = None
    last_exc = None
    # Role propagation: retry provider creation on its propagation errors for up to six
    # create-and-settle rounds (6 x (150 s settle + 10 s)).
    left = ctx.time_left()
    cp_deadline = time.monotonic() + (960.0 if left is None else min(960.0, max(1.0, left - 5.0)))
    while time.monotonic() < cp_deadline:
        cp_name = ctx.unique_name("sim2real-mi-cp-")
        try:
            cp = ecs.create_capacity_provider(
                name=cp_name,
                cluster=cluster_name,
                managedInstancesProvider={
                    "infrastructureRoleArn": infra_role_arn,
                    "instanceLaunchTemplate": {
                        "ec2InstanceProfileArn": profile_arn,
                        "networkConfiguration": {"subnets": subnets, "securityGroups": [sg_id]},
                        "monitoring": "basic",
                    },
                },
            )["capacityProvider"]
            candidate_arn = cp["capacityProviderArn"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            last_exc = e
            if code == "UnsupportedFeatureException":
                raise AssertionError(f"unreachable: ECS Managed Instances unsupported here: {e}")
            if code in ("InvalidParameterException", "AccessDeniedException", "ClientException"):
                time.sleep(2)
                continue
            raise

        desc = _terminal_cp(ecs, candidate_arn)
        if desc["status"] == "ACTIVE":
            cp_arn = candidate_arn
            break
        last_exc = (
            f"Managed Instances capacity provider {candidate_arn} went INACTIVE while provisioning: "
            f"updateStatus={desc.get('updateStatus')} reason={desc.get('updateStatusReason')}"
        )
        if not _is_role_propagation_race(desc):
            raise AssertionError(last_exc)
        # an INACTIVE provider from a role-propagation race is terminal for that provider only:
        # delete it and retry with a fresh one
        try:
            ecs.delete_capacity_provider(capacityProvider=candidate_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ClientException":
                raise
        time.sleep(2)
    if cp_arn is None:
        raise AssertionError(f"unreachable: could not create Managed Instances capacity provider: {last_exc}")
    ctx.on_cleanup(lambda: _delete_capacity_provider_and_wait(ecs, cp_arn))

    return {"cluster_arn": cluster_arn, "cp_arn": cp_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
