"""daemon-create-active-lifecycle."""
from __future__ import annotations

import json
import time
import uuid

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "daemon-create-active-lifecycle"
GROUP = "state-machine"
SERVICES = ["ecs"]

_INFRA_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonECSInfrastructureRolePolicyForManagedInstances"
_INSTANCE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"


# Marks a failure where an accepted resource never converged, so it is reported as a
# behavioural failure rather than an environment error.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDaemon on a Managed Instances capacity provider is ACTIVE at once with a deploymentArn;
    DeleteDaemon returns DELETE_IN_PROGRESS and DescribeDaemon then raises DaemonNotFoundException."""
    ecs = ctx.client("ecs")
    infra = _setup_managed_instances_capacity_provider(ctx)
    td_arn = _register_daemon_task_def(ctx, ctx.unique_name("sim2real-daemon-td-"))

    created = ecs.create_daemon(
        daemonName=ctx.unique_name("sim2real-daemon-"),
        clusterArn=infra["cluster_arn"],
        daemonTaskDefinitionArn=td_arn,
        capacityProviderArns=[infra["capacity_provider_arn"]],
    )
    daemon_arn = created["daemonArn"]
    assert created["status"] == "ACTIVE", f"expected ACTIVE on create, got {created['status']}"
    assert created.get("deploymentArn"), "CreateDaemon response missing the initial deploymentArn"
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_daemon(daemonArn=daemon_arn)))

    described = ecs.describe_daemon(daemonArn=daemon_arn)["daemon"]
    assert described["daemonArn"] == daemon_arn
    assert described["status"] == "ACTIVE"
    assert described["clusterArn"] == infra["cluster_arn"]

    deleted = ecs.delete_daemon(daemonArn=daemon_arn)
    assert deleted["status"] == "DELETE_IN_PROGRESS", f"expected DELETE_IN_PROGRESS, got {deleted['status']}"

    def _probe():
        try:
            return ("present", ecs.describe_daemon(daemonArn=daemon_arn)["daemon"]["status"], None)
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] == "DaemonNotFoundException":
                return ("absent", None, err.response["Error"].get("Message"))
            raise

    outcome = _poll_until(_probe, lambda o: o[0] == "absent", timeout_s=120.0, interval_s=5.0)
    assert outcome[0] == "absent", "DescribeDaemon should eventually raise DaemonNotFoundException after deletion"
    assert outcome[2] == f"Daemon not found: {daemon_arn}", f"unexpected DaemonNotFoundException message: {outcome[2]!r}"


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
        deadline = time.monotonic() + 600
        for subnet_id in made["subnets"]:
            while True:
                try:
                    ec2.delete_subnet(SubnetId=subnet_id)
                    break
                except botocore.exceptions.ClientError as exc:
                    if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                        raise
                    time.sleep(2)
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


_GONE_CODES = ("NoSuchEntity", "DaemonNotFoundException", "DaemonNotActiveException", "ClusterNotFoundException")
_CLUSTER_BUSY_CODES = (
    "ClusterContainsCapacityProviderException",
    "ClusterContainsContainerInstancesException",
    "ClusterContainsServicesException",
    "ClusterContainsTasksException",
    "UpdateInProgressException",
)


def _safe(fn) -> None:
    """Run a teardown call: a resource already gone is done, any other error raises."""
    try:
        fn()
    except ClientError as err:
        error = err.response["Error"]
        if error["Code"] not in _GONE_CODES and "does not exist" not in error.get("Message", ""):
            raise


def _role_visible(iam, role_name) -> bool:
    try:
        iam.get_role(RoleName=role_name)
    except botocore.exceptions.ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
        return False
    return True


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


def _delete_capacity_provider_and_wait(ecs, cp_arn) -> None:
    ecs.delete_capacity_provider(capacityProvider=cp_arn)
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            state = ecs.describe_capacity_providers(capacityProviders=[cp_arn])["capacityProviders"]
            if not state or state[0]["status"] == "INACTIVE":
                return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
            return
        time.sleep(3.0)


def _delete_cluster_retrying(ecs, cluster_arn) -> None:
    """Delete the cluster, retrying while ECS still releases what it contains."""
    deadline = time.monotonic() + 120.0
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code not in _CLUSTER_BUSY_CODES or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


def _register_daemon_task_def(ctx, family, image="public.ecr.aws/amazonlinux/amazonlinux:2023", command=None, memory=128):
    ecs = ctx.client("ecs")
    arn = ecs.register_daemon_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "agent",
                "image": image,
                "essential": True,
                "memory": memory,
                "command": command or ["sleep", "3600"],
            }
        ],
    )["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition=arn)))
    return arn


def _setup_managed_instances_capacity_provider(ctx) -> dict:
    """Provision the IAM roles, cluster, and Managed Instances capacity
    provider that ECS Managed Daemons require. Registers teardown for every
    resource it creates and raises AssertionError (never skips) if the
    account/region can't satisfy the prerequisites."""

    ecs = ctx.client("ecs")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    if not hasattr(ecs, "create_daemon"):
        raise AssertionError("installed botocore/boto3 has no ECS Managed Daemons operations")
    try:
        subnet_ids, sg_id = _own_network(ctx)

        suffix = uuid.uuid4().hex[:10]

        infra_role_name = ctx.unique_name("sim2real-ecs-infra-")
        iam.create_role(
            RoleName=infra_role_name,
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Principal": {"Service": "ecs.amazonaws.com"}, "Action": "sts:AssumeRole"}
                    ],
                }
            ),
        )
        ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=infra_role_name)))
        iam.attach_role_policy(RoleName=infra_role_name, PolicyArn=_INFRA_POLICY_ARN)
        ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=infra_role_name, PolicyArn=_INFRA_POLICY_ARN)))
        infra_role_arn = iam.get_role(RoleName=infra_role_name)["Role"]["Arn"]

        # AmazonECSInfrastructureRolePolicyForManagedInstances scopes iam:PassRole
        # to role names starting with "ecsInstanceRole".
        instance_role_name = f"ecsInstanceRole{suffix}"
        iam.create_role(
            RoleName=instance_role_name,
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
                    ],
                }
            ),
        )
        ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=instance_role_name)))
        iam.attach_role_policy(RoleName=instance_role_name, PolicyArn=_INSTANCE_POLICY_ARN)
        ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=instance_role_name, PolicyArn=_INSTANCE_POLICY_ARN)))

        profile_name = instance_role_name
        iam.create_instance_profile(InstanceProfileName=profile_name)
        ctx.on_cleanup(lambda: _safe(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name)))
        iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=instance_role_name)
        ctx.on_cleanup(
            lambda: _safe(
                lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=instance_role_name)
            )
        )
        profile_arn = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]["Arn"]

        _poll_until(
            lambda: _role_visible(iam, infra_role_name),
            bool,
            timeout_s=30.0,
            interval_s=2.0,
        )

        cluster_name = ctx.unique_name("sim2real-ecs-daemon-cl-")
        cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
        ctx.on_cleanup(lambda: _safe(lambda: _delete_cluster_retrying(ecs, cluster_arn)))

        def _describe_cp(arn):
            return ecs.describe_capacity_providers(capacityProviders=[arn])["capacityProviders"][0]

        # ECS assumes infra_role_arn cross-service before a capacity provider can go ACTIVE, and a
        # role this fresh is sometimes not yet visible to that assumption: the provider then goes
        # INACTIVE with a ServiceAccessDeniedException reason, which is terminal for that provider
        # but transient for the account. Retry the whole create (a new name each time) against the
        # provider's own reported reason, bounded by a deadline, rather than trusting a fixed sleep
        # to have waited long enough.
        propagation_deadline = time.monotonic() + 180.0
        cp_arn = None
        attempt = 0
        while True:
            attempt += 1
            cp_kwargs = dict(
                name=ctx.unique_name(f"sim2real-ecs-daemon-cp-{attempt}-"),
                cluster=cluster_name,
                managedInstancesProvider={
                    "infrastructureRoleArn": infra_role_arn,
                    "instanceLaunchTemplate": {
                        "ec2InstanceProfileArn": profile_arn,
                        "networkConfiguration": {"subnets": subnet_ids, "securityGroups": [sg_id]},
                    },
                },
            )
            this_arn = None
            last_err = None
            create_deadline = time.monotonic() + 48.0
            while time.monotonic() < create_deadline:
                try:
                    this_arn = ecs.create_capacity_provider(**cp_kwargs)["capacityProvider"]["capacityProviderArn"]
                    break
                except botocore.exceptions.ClientError as err:
                    last_err = err
                    time.sleep(2.0)
            if this_arn is None:
                raise AssertionError(f"could not create managed-instances capacity provider: {last_err}")
            ctx.on_cleanup(lambda arn=this_arn: _safe(lambda: _delete_capacity_provider_and_wait(ecs, arn)))

            cp_state = _poll_until(
                lambda: _describe_cp(this_arn), lambda cp_: cp_["status"] != "PROVISIONING", timeout_s=150.0, interval_s=5.0
            )
            if cp_state["status"] == "ACTIVE":
                cp_arn = this_arn
                break

            reason = str(cp_state.get("updateStatusReason") or cp_state.get("updateStatus") or "")
            is_role_propagation_race = "ServiceAccessDeniedException" in reason and "ECSInfrastructureRole" in reason
            if not is_role_propagation_race or time.monotonic() >= propagation_deadline:
                raise _never_ready(
                    f"managed-instances capacity provider never reached ACTIVE "
                    f"(status={cp_state['status']}, reason={reason})",
                )
            time.sleep(2.0)

        return {"cluster_arn": cluster_arn, "cluster_name": cluster_name, "capacity_provider_arn": cp_arn}
    except AssertionError:
        raise
    except Exception as err:  # pragma: no cover - defensive: any prereq failure still fails, never skips
        raise AssertionError(f"managed-instances prerequisite setup failed: {err}") from err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
