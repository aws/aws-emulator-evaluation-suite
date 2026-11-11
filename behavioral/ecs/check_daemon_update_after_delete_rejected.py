"""daemon-update-after-delete-rejected."""
from __future__ import annotations

import json
import time
import uuid

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "daemon-update-after-delete-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]

_INFRA_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonECSInfrastructureRolePolicyForManagedInstances"
_INSTANCE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"


# Marks a failure where an accepted resource never converged, so it is reported as a
# behavioural failure rather than an environment error.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state. Returns the exception rather
    than raising it, so a call site keeps its ``from exc`` chaining."""
    return AssertionError(f"{STATE_MARKER}: {msg}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateDaemon works while ACTIVE but, once DeleteDaemon starts, is rejected with
    InvalidParameterException and leaves the task definition unchanged; a second DeleteDaemon
    succeeds and echoes the same DELETE_IN_PROGRESS deployment."""
    from botocore.exceptions import ClientError

    ecs = ctx.client("ecs")
    infra = _setup_managed_instances_capacity_provider(ctx)
    family = ctx.unique_name("sim2real-daemon-td-")
    td_v1 = _register_daemon_task_def(ctx, family, memory=128)
    td_v2 = _register_daemon_task_def(ctx, family, memory=256)
    td_v3 = _register_daemon_task_def(ctx, family, memory=384)

    created = ecs.create_daemon(
        daemonName=ctx.unique_name("sim2real-daemon-"),
        clusterArn=infra["cluster_arn"],
        daemonTaskDefinitionArn=td_v1,
        capacityProviderArns=[infra["capacity_provider_arn"]],
        tags=[{"key": "sim2real:managed", "value": "true"}, {"key": "sim2real:check", "value": CHECK}],
    )
    daemon_arn = created["daemonArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_daemon(daemonArn=daemon_arn)))

    updated = ecs.update_daemon(
        daemonArn=daemon_arn,
        daemonTaskDefinitionArn=td_v2,
        capacityProviderArns=[infra["capacity_provider_arn"]],
    )
    assert updated["status"] == "ACTIVE", f"positive control: expected ACTIVE after update, got {updated['status']!r}"
    reflected = ecs.describe_daemon(daemonArn=daemon_arn)["daemon"]
    assert reflected["deploymentArn"] == updated["deploymentArn"], (
        "positive control: DescribeDaemon should reflect the update's new deployment, "
        f"got {reflected['deploymentArn']!r} instead of {updated['deploymentArn']!r}"
    )

    deleted = ecs.delete_daemon(daemonArn=daemon_arn)
    assert deleted["status"] == "DELETE_IN_PROGRESS"

    code, msg = None, None
    try:
        ecs.update_daemon(
            daemonArn=daemon_arn,
            daemonTaskDefinitionArn=td_v3,
            capacityProviderArns=[infra["capacity_provider_arn"]],
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        msg = err.response["Error"].get("Message", "")
    else:
        raise AssertionError("UpdateDaemon on a DELETE_IN_PROGRESS daemon unexpectedly succeeded")
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}: {msg}"
    assert msg == f"{daemon_arn} deletion is in progress", f"unexpected deletion-in-progress message: {msg!r}"

    still = ecs.describe_daemon(daemonArn=daemon_arn)["daemon"]
    still_deployment = ecs.describe_daemon_deployments(daemonDeploymentArns=[still["deploymentArn"]])[
        "daemonDeployments"
    ][0]
    still_revision = ecs.describe_daemon_revisions(
        daemonRevisionArns=[still_deployment["targetDaemonRevision"]["arn"]]
    )["daemonRevisions"][0]
    assert still_revision["daemonTaskDefinitionArn"] == td_v2, (
        "rejected UpdateDaemon should not have changed the daemon's target task definition; "
        f"expected {td_v2!r}, got {still_revision['daemonTaskDefinitionArn']!r}"
    )

    redelete = ecs.delete_daemon(daemonArn=daemon_arn)
    assert redelete["status"] == "DELETE_IN_PROGRESS", (
        f"expected the repeat delete to echo DELETE_IN_PROGRESS, got {redelete['status']!r}"
    )
    assert redelete["deploymentArn"] == deleted["deploymentArn"], (
        "a repeat DeleteDaemon should echo the same deletion deployment, not start a new one; "
        f"expected {deleted['deploymentArn']!r}, got {redelete['deploymentArn']!r}"
    )


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
    """Delete the provider once the daemon releases it, then wait until it is INACTIVE."""
    deadline = time.monotonic() + 120.0
    while True:
        try:
            ecs.delete_capacity_provider(capacityProvider=cp_arn)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("UpdateInProgressException", "ResourceInUseException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(2.0)
    deadline = time.monotonic() + 300.0
    status = None
    while time.monotonic() < deadline:
        try:
            state = ecs.describe_capacity_providers(capacityProviders=[cp_arn])["capacityProviders"]
            if not state or state[0]["status"] == "INACTIVE":
                return
            status = state[0]["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
            return
        time.sleep(2.0)
    raise AssertionError(f"capacity provider {cp_arn} still {status} after 300s")


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
    """Provision the IAM roles, cluster, and Managed Instances capacity provider that ECS Managed
    Daemons require, with teardown; raises AssertionError if a prerequisite is unavailable."""

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
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
        ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=infra_role_name)))
        iam.attach_role_policy(RoleName=infra_role_name, PolicyArn=_INFRA_POLICY_ARN)
        ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=infra_role_name, PolicyArn=_INFRA_POLICY_ARN)))
        infra_role_arn = iam.get_role(RoleName=infra_role_name)["Role"]["Arn"]

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
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
        cluster_arn = ecs.create_cluster(
            clusterName=cluster_name, tags=[{"key": "sim2real:managed", "value": "true"}]
        )["cluster"]["clusterArn"]
        ctx.on_cleanup(lambda: _safe(lambda: _delete_cluster_retrying(ecs, cluster_arn)))

        cp_name = ctx.unique_name("sim2real-ecs-daemon-cp-")
        cp_kwargs = dict(
            name=cp_name,
            cluster=cluster_name,
            managedInstancesProvider={
                "infrastructureRoleArn": infra_role_arn,
                "instanceLaunchTemplate": {
                    "ec2InstanceProfileArn": profile_arn,
                    "networkConfiguration": {"subnets": subnet_ids, "securityGroups": [sg_id]},
                    "instanceRequirements": {
                        "vCpuCount": {"min": 1, "max": 2},
                        "memoryMiB": {"min": 512, "max": 2048},
                    },
                },
            },
            tags=[{"key": "sim2real:managed", "value": "true"}],
        )
        cp_arn = None
        last_err = None
        create_deadline = time.monotonic() + 48.0
        while time.monotonic() < create_deadline:
            try:
                cp_arn = ecs.create_capacity_provider(**cp_kwargs)["capacityProvider"]["capacityProviderArn"]
                break
            except botocore.exceptions.ClientError as err:
                last_err = err
                time.sleep(2.0)
        if cp_arn is None:
            raise AssertionError(f"could not create managed-instances capacity provider: {last_err}")
        ctx.on_cleanup(lambda: _safe(lambda: _delete_capacity_provider_and_wait(ecs, cp_arn)))

        def _describe_cp():
            return ecs.describe_capacity_providers(capacityProviders=[cp_arn])["capacityProviders"][0]

        cp_state = _poll_until(_describe_cp, lambda cp_: cp_["status"] != "PROVISIONING", timeout_s=150.0, interval_s=5.0)
        if cp_state["status"] != "ACTIVE":
            raise _never_ready(
                f"managed-instances capacity provider never reached ACTIVE (status={cp_state['status']})",
            )

        return {"cluster_arn": cluster_arn, "cluster_name": cluster_name, "capacity_provider_arn": cp_arn}
    except AssertionError:
        raise
    except Exception as err:  # pragma: no cover - defensive: any prereq failure fails the check, never skips
        raise AssertionError(f"managed-instances prerequisite setup failed: {err}") from err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
