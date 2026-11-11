"""daemon-lifecycle-create-to-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "daemon-lifecycle-create-to-delete"
GROUP = "state-machine"
SERVICES = ["ecs"]


_ECS_TAGS = [{"key": "sim2real:managed", "value": "true"}]
_IAM_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDaemon reaches ACTIVE, UpdateDaemon rolls a new revision, DeleteDaemon tears it down."""

    env = _setup_managed_instances_env(ctx)
    ecs = ctx.client("ecs")

    td_arn_1 = _register_daemon_task_def(ctx)
    daemon_name = ctx.unique_name("sim2real-daemon-")

    create_resp = ecs.create_daemon(
        daemonName=daemon_name,
        clusterArn=env["cluster_arn"],
        daemonTaskDefinitionArn=td_arn_1,
        capacityProviderArns=[env["capacity_provider_arn"]],
        tags=_ECS_TAGS,
    )
    daemon_arn = create_resp["daemonArn"]
    assert create_resp["status"] == "ACTIVE", f"expected ACTIVE on create, got {create_resp['status']}"
    first_deployment_arn = create_resp["deploymentArn"]
    ctx.on_cleanup(lambda: _delete_daemon_best_effort(ecs, daemon_arn))

    desc = ecs.describe_daemon(daemonArn=daemon_arn)["daemon"]
    assert desc["status"] == "ACTIVE", f"expected ACTIVE on DescribeDaemon, got {desc['status']}"
    assert desc["daemonArn"] == daemon_arn, f"expected daemonArn {daemon_arn}, got {desc['daemonArn']}"
    assert desc["deploymentArn"] == first_deployment_arn, (
        f"expected DescribeDaemon to reflect the create deployment {first_deployment_arn}, "
        f"got {desc['deploymentArn']}"
    )

    # UpdateDaemon: point the daemon at a new task definition revision -> triggers a new deployment
    td_arn_2 = _register_daemon_task_def(ctx)
    update_resp = ecs.update_daemon(
        daemonArn=daemon_arn,
        daemonTaskDefinitionArn=td_arn_2,
        capacityProviderArns=[env["capacity_provider_arn"]],
    )
    assert update_resp["daemonArn"] == daemon_arn, f"expected daemonArn {daemon_arn}, got {update_resp['daemonArn']}"
    assert update_resp["status"] == "ACTIVE", f"expected ACTIVE on UpdateDaemon, got {update_resp['status']}"
    second_deployment_arn = update_resp["deploymentArn"]
    assert second_deployment_arn != first_deployment_arn, "UpdateDaemon must mint a new deployment ARN"

    desc2 = ecs.describe_daemon(daemonArn=daemon_arn)["daemon"]
    assert desc2["deploymentArn"] == second_deployment_arn, "DescribeDaemon must reflect the latest deployment"

    # DeleteDaemon: ACTIVE -> DELETE_IN_PROGRESS
    delete_resp = ecs.delete_daemon(daemonArn=daemon_arn)
    assert delete_resp["daemonArn"] == daemon_arn, f"expected daemonArn {daemon_arn}, got {delete_resp['daemonArn']}"
    assert delete_resp["status"] == "DELETE_IN_PROGRESS", f"expected DELETE_IN_PROGRESS, got {delete_resp['status']}"

    # The terminal assertion is an INDEPENDENT read at the destination, through DescribeDaemon --
    # never the mutating DeleteDaemon call's own response. DELETE_IN_PROGRESS is transient, so the
    # read is polled until the daemon is gone and the terminal refusal is graded.
    from botocore.exceptions import ClientError

    def _post_delete():
        try:
            return ("present", ecs.describe_daemon(daemonArn=daemon_arn)["daemon"]["status"], None)
        except ClientError as err:
            return ("absent", err.response["Error"]["Code"], err.response["Error"].get("Message"))

    gone = _poll_until(_post_delete, lambda o: o[0] == "absent", timeout_s=180.0, interval_s=5.0)
    assert gone[1] == "DaemonNotFoundException", (
        f"expected DaemonNotFoundException on DescribeDaemon after delete, got {gone[1]}"
    )
    assert gone[2] == f"Daemon not found: {daemon_arn}", f"unexpected DaemonNotFoundException message: {gone[2]!r}"


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
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 1, "MaxAttempts": 60})
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


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _delete_capacity_provider_and_wait(ecs, cp_arn):
    """DeleteCapacityProvider is asynchronous; the cluster refuses deletion while the provider is
    still attached, so wait until the provider reports INACTIVE or is gone."""
    ecs.delete_capacity_provider(capacityProvider=cp_arn)
    _poll_until(
        lambda: [c["status"] for c in ecs.describe_capacity_providers(capacityProviders=[cp_arn])["capacityProviders"]],
        lambda statuses: not statuses or statuses[0] == "INACTIVE",
        timeout_s=600.0,
        interval_s=10.0,
    )


def _delete_cluster_when_detached(ecs, cluster_arn):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 300.0
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_arn)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
            time.sleep(10.0)


def _delete_daemon_best_effort(ecs, daemon_arn):
    from botocore.exceptions import ClientError

    try:
        ecs.delete_daemon(daemonArn=daemon_arn)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        if code not in ("DaemonNotFoundException", "DaemonNotActiveException"):
            raise


def _register_daemon_task_def(ctx):
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-daemon-td-")
    resp = ecs.register_daemon_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "agent",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
                "cpu": 128,
                "memory": 256,
                "essential": True,
                "command": ["sleep", "3600"],
            }
        ],
        tags=_ECS_TAGS,
    )
    arn = resp["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: _delete_daemon_task_def_best_effort(ecs, arn))
    return arn


def _delete_daemon_task_def_best_effort(ecs, arn):
    # DeleteDaemonTaskDefinition is idempotent on a non-ACTIVE revision, so a real error here is
    # never "already gone" and must not be swallowed.
    ecs.delete_daemon_task_definition(daemonTaskDefinition=arn)


def _setup_managed_instances_env(ctx):
    """Provision the cluster + ECS Managed Instances capacity provider that ECS daemons require.

    Raises AssertionError (never skips) if the account/region cannot satisfy this
    prerequisite (e.g. the IAM/EC2 setup needed to prove it out isn't permitted).
    """
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ecs = ctx.client("ecs")

    infra_role_name = ctx.unique_name("sim2real-ecs-infra-")
    instance_role_name = ctx.unique_name("sim2real-ecs-instrole-")
    profile_name = ctx.unique_name("sim2real-ecs-instprof-")

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
    infra_policy_arn = "arn:aws:iam::aws:policy/AmazonECSInfrastructureRolePolicyForManagedInstances"
    instance_policy_arn = "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"

    try:
        infra_role_arn = iam.create_role(
            RoleName=infra_role_name, AssumeRolePolicyDocument=infra_trust, Tags=_IAM_TAGS
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=infra_role_name))
        iam.attach_role_policy(RoleName=infra_role_name, PolicyArn=infra_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=infra_role_name, PolicyArn=infra_policy_arn))

        iam.create_role(
            RoleName=instance_role_name, AssumeRolePolicyDocument=instance_trust, Tags=_IAM_TAGS
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=instance_role_name))
        iam.attach_role_policy(RoleName=instance_role_name, PolicyArn=instance_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=instance_role_name, PolicyArn=instance_policy_arn))

        iam.create_instance_profile(InstanceProfileName=profile_name, Tags=_IAM_TAGS)
        ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
        iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=instance_role_name)
        ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=instance_role_name))
        profile_arn = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]["Arn"]
    except ClientError as err:
        raise AssertionError(
            f"unreachable: cannot provision IAM prerequisites for ECS Managed Instances ({err.response['Error']['Code']})"
        )

    subnet_ids, sg_id = _own_network(ctx)

    cluster_name = ctx.unique_name("sim2real-daemon-cluster-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name, tags=_ECS_TAGS)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_detached(ecs, cluster_arn))

    cp_name = ctx.unique_name("sim2real-mi-cp-")
    deadline = time.monotonic() + 90.0
    cp_arn = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = ecs.create_capacity_provider(
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
                tags=_ECS_TAGS,
            )
            cp_arn = resp["capacityProvider"]["capacityProviderArn"]
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            last_err = err
            if code in ("InvalidParameterException", "ClientException") and time.monotonic() < deadline - 5:
                time.sleep(5)
                continue
            raise AssertionError(
                "unreachable: ECS Managed Instances capacity provider unavailable in this "
                f"account/region ({code}): {err}"
            )
    if cp_arn is None:
        raise AssertionError(f"unreachable: could not create Managed Instances capacity provider: {last_err}")
    ctx.on_cleanup(lambda: _delete_capacity_provider_and_wait(ecs, cp_arn))

    def _cp_status():
        d = ecs.describe_capacity_providers(capacityProviders=[cp_arn])["capacityProviders"]
        return d[0]["status"] if d else None

    try:
        status = _poll_until(_cp_status, lambda s: s == "ACTIVE", timeout_s=180.0, interval_s=5.0)
    except AssertionError as err:
        raise AssertionError(
            f"unreachable: Managed Instances capacity provider never reached ACTIVE ({err})",
        )
    assert status == "ACTIVE", f"expected ACTIVE after poll, got {status}"

    return {"cluster_arn": cluster_arn, "cluster_name": cluster_name, "capacity_provider_arn": cp_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
