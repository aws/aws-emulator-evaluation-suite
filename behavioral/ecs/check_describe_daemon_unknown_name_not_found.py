"""describe-daemon-unknown-name-not-found."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "describe-daemon-unknown-name-not-found"
GROUP = "error-semantics"
SERVICES = ["ecs"]
_CP_DOES_NOT_EXIST = "The specified capacity provider does not exist. Specify a valid name or ARN and try again."

_MI_INSTANCE_POLICY = "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"
_MI_INFRA_POLICY = "arn:aws:iam::aws:policy/AmazonECSInfrastructureRolePolicyForManagedInstances"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDaemon for a well-formed ARN of a never-created daemon returns DaemonNotFoundException,
    not an empty success, while a real daemon in the same cluster describes successfully."""

    ecs = ctx.client("ecs")
    sts = ctx.client("sts")

    cluster_name = ctx.unique_name("sim2real-ecs-nodaemon-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real-check", "value": CHECK}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    real_daemon_arn = _create_real_daemon(ctx, ecs, cluster_name, cluster_arn)

    # Positive control: DescribeDaemon must succeed on a real daemon before we trust
    # it to fail on one that was never created -- otherwise a target that rejects
    # every DescribeDaemon call would pass this check for the wrong reason.
    control = ecs.describe_daemon(daemonArn=real_daemon_arn)["daemon"]
    assert control["daemonArn"] == real_daemon_arn, (
        f"expected positive control to describe {real_daemon_arn}, got {control.get('daemonArn')}"
    )

    account_id = sts.get_caller_identity()["Account"]
    fake_daemon_name = ctx.unique_name("sim2real-nodaemon-name-")
    fake_daemon_arn = f"arn:aws:ecs:{ctx.region}:{account_id}:daemon/{cluster_name}/{fake_daemon_name}"

    code, message = _error(lambda: ecs.describe_daemon(daemonArn=fake_daemon_arn))
    if code in ("UnsupportedFeatureException", "AccessDeniedException"):
        raise AssertionError(f"ECS daemon feature unavailable/unauthorized in this account/region: {code}")
    assert code == "DaemonNotFoundException", f"expected DaemonNotFoundException, got {code!r}"
    assert message == f"Daemon not found: {fake_daemon_arn}", f"unexpected message: {message!r}"


# ===== helpers =====


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not be reported as an
    error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = [
        s["SubnetId"]
        for s in ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ]
        ).get("Subnets", [])
    ]
    if not subnets:
        raise AssertionError("no network subnets available in this account/region")
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    ).get("SecurityGroups", [])
    if not sgs:
        raise AssertionError("no default security group available in this account/region")
    return subnets, sgs[0]["GroupId"]


def _create_real_daemon(ctx, ecs, cluster_name, cluster_arn) -> str:
    """Provision the minimal Managed Instances capacity provider a real ECS daemon requires, then
    create one. CreateDaemon does not wait for the capacity provider to reach ACTIVE -- daemon
    placement is lazy -- so this does not pay for host launch."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    subnets, sg = _default_network(ctx)

    instance_role = ctx.unique_name("ecsInstanceRole-")[:64]
    instance_role_arn = iam.create_role(
        RoleName=instance_role,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=instance_role))
    iam.attach_role_policy(RoleName=instance_role, PolicyArn=_MI_INSTANCE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=instance_role, PolicyArn=_MI_INSTANCE_POLICY))
    iam.create_instance_profile(InstanceProfileName=instance_role)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=instance_role))
    iam.add_role_to_instance_profile(InstanceProfileName=instance_role, RoleName=instance_role)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=instance_role, RoleName=instance_role)
    )
    profile_arn = iam.get_instance_profile(InstanceProfileName=instance_role)["InstanceProfile"]["Arn"]

    infra_role = ctx.unique_name("ecsInfra-")[:64]
    infra_role_arn = iam.create_role(
        RoleName=infra_role,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "ecs.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=infra_role))
    iam.attach_role_policy(RoleName=infra_role, PolicyArn=_MI_INFRA_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=infra_role, PolicyArn=_MI_INFRA_POLICY))
    iam.put_role_policy(
        RoleName=infra_role,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": instance_role_arn}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=infra_role, PolicyName="inline"))

    cp_name = ctx.unique_name("cp-")
    deadline = time.monotonic() + 90
    while True:
        try:
            ecs.create_capacity_provider(
                name=cp_name,
                cluster=cluster_name,
                managedInstancesProvider={
                    "infrastructureRoleArn": infra_role_arn,
                    "instanceLaunchTemplate": {
                        "ec2InstanceProfileArn": profile_arn,
                        "networkConfiguration": {"subnets": subnets[:1], "securityGroups": [sg]},
                        "monitoring": "basic",
                    },
                },
                tags=[{"key": "sim2real-check", "value": CHECK}],
            )
            break
        except ClientError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(f"could not provision a Managed Instances capacity provider: {exc}") from None
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_capacity_provider_and_wait(ecs, cp_name))
    cp_arn = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0][
        "capacityProviderArn"
    ]

    dtd_arn = ecs.register_daemon_task_definition(
        family=ctx.unique_name("daemontd-"),
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "cpu": 64,
                "memory": 128,
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition=dtd_arn))

    daemon_arn = ecs.create_daemon(
        clusterArn=cluster_arn,
        daemonName=ctx.unique_name("daemon-"),
        capacityProviderArns=[cp_arn],
        daemonTaskDefinitionArn=dtd_arn,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["daemonArn"]
    ctx.on_cleanup(lambda: ecs.delete_daemon(daemonArn=daemon_arn))
    return daemon_arn


def _delete_capacity_provider_and_wait(ecs, cp_name, timeout_s=600.0, interval_s=10.0):
    """Teardown: DeleteCapacityProvider, retried while a daemon teardown still holds the
    provider (UpdateInProgressException), then wait until it is gone, so the cluster delete
    that runs after it does not find a cluster-scoped provider still attached. A provider
    that no longer exists counts as deleted. Raises once the deadline passes."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_capacity_provider(capacityProvider=cp_name)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and err.get("Message") == _CP_DOES_NOT_EXIST:
                return
            if err["Code"] != "UpdateInProgressException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)
    while True:
        cps = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"]
        if not cps or cps[0]["status"] == "INACTIVE":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"capacity provider {cp_name} still {cps[0]['status']} after {timeout_s}s")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
