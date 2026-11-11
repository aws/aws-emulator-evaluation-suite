"""daemon-ops-on-missing-cluster-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "daemon-ops-on-missing-cluster-not-found"
GROUP = 'error-semantics'
SERVICES = ['ecs']

_MI_INSTANCE_POLICY = "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"
_MI_INFRA_POLICY = "arn:aws:iam::aws:policy/AmazonECSInfrastructureRolePolicyForManagedInstances"
_ECS_TAGS = [{"key": "sim2real:managed", "value": "true"}, {"key": "sim2real:prefix", "value": "sim2real-behav"}]
_IAM_TAGS = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises:
    accepting input that AWS refuses must not be reported as a mere error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


_CP_GONE = "The specified capacity provider does not exist. Specify a valid name or ARN and try again."


def _retry_while(fn, retry_codes, *, timeout_s, interval_s=10):
    """Teardown call that retries while the error code is one of retry_codes; any other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in retry_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _delete_capacity_provider_and_wait(ecs, cp_name):
    """Delete the capacity provider once the daemon releases it, then wait until it is gone, so the
    cluster delete and the IAM teardown that follow are not blocked by a deprovisioning provider."""
    try:
        _retry_while(
            lambda: ecs.delete_capacity_provider(capacityProvider=cp_name),
            {"UpdateInProgressException", "ResourceInUseException"},
            timeout_s=90,
        )
    except ClientError as exc:
        if exc.response["Error"].get("Message", "") != _CP_GONE:
            raise
    deadline = time.monotonic() + 120
    while True:
        cps = ecs.describe_capacity_providers(capacityProviders=[cp_name]).get("capacityProviders", [])
        if not cps or cps[0].get("status") == "INACTIVE":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"capacity provider {cp_name} still {cps[0].get('status')} after 120s")
        time.sleep(10)


def _delete_cluster_when_detached(ecs, cluster):
    _retry_while(
        lambda: ecs.delete_cluster(cluster=cluster),
        {"ClientException", "UpdateInProgressException", "ClusterContainsCapacityProviderException"},
        timeout_s=60,
    )


def _swap_cluster_in_arn(arn: str, old_cluster: str, new_cluster: str) -> str:
    return arn.replace(f"/{old_cluster}/", f"/{new_cluster}/", 1)


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


def _create_managed_instances_cp(ctx, ecs, cluster):
    """Provision a cluster-scoped Managed Instances capacity provider (no hosts launch until
    placement is needed); the caller turns an unusable prerequisite into an AssertionError."""
    iam = ctx.client("iam")
    subnets, sg = _default_network(ctx)

    trust_ec2 = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    instance_role = ctx.unique_name("ecsInstanceRole-")[:64]
    instance_role_arn = iam.create_role(
        RoleName=instance_role, AssumeRolePolicyDocument=json.dumps(trust_ec2), Tags=_IAM_TAGS
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=instance_role))
    iam.attach_role_policy(RoleName=instance_role, PolicyArn=_MI_INSTANCE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=instance_role, PolicyArn=_MI_INSTANCE_POLICY))
    iam.create_instance_profile(InstanceProfileName=instance_role, Tags=_IAM_TAGS)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=instance_role))
    iam.add_role_to_instance_profile(InstanceProfileName=instance_role, RoleName=instance_role)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=instance_role, RoleName=instance_role
        )
    )
    profile_arn = iam.get_instance_profile(InstanceProfileName=instance_role)["InstanceProfile"]["Arn"]

    trust_ecs = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    infra_role = ctx.unique_name("ecsInfra-")[:64]
    infra_role_arn = iam.create_role(
        RoleName=infra_role, AssumeRolePolicyDocument=json.dumps(trust_ecs), Tags=_IAM_TAGS
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
                "Statement": [
                    {"Effect": "Allow", "Action": "iam:PassRole", "Resource": instance_role_arn}
                ],
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
                cluster=cluster,
                managedInstancesProvider={
                    "infrastructureRoleArn": infra_role_arn,
                    "instanceLaunchTemplate": {
                        "ec2InstanceProfileArn": profile_arn,
                        "networkConfiguration": {"subnets": subnets[:1], "securityGroups": [sg]},
                        "monitoring": "basic",
                    },
                },
                tags=_ECS_TAGS,
            )
            break
        except ClientError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"could not provision a Managed Instances capacity provider: {exc}"
                ) from None
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_capacity_provider_and_wait(ecs, cp_name))
    return cp_name


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Against a nonexistent cluster, Create/Delete/UpdateDaemon return ClusterNotFoundException,
    DescribeDaemon returns DaemonNotFoundException, and ListDaemons returns an empty result.
    """
    ecs = ctx.client("ecs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    try:
        cluster = ecs.create_cluster(
            clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"), tags=_ECS_TAGS
        )["cluster"]
        cluster_name = cluster["clusterName"]
        ctx.on_cleanup(lambda: _delete_cluster_when_detached(ecs, cluster_name))
        cp_name = _create_managed_instances_cp(ctx, ecs, cluster_name)
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
            tags=_ECS_TAGS,
        )["daemonTaskDefinitionArn"]
        ctx.on_cleanup(lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition=dtd_arn))
        daemon = ecs.create_daemon(
            clusterArn=cluster["clusterArn"],
            daemonName=ctx.unique_name("daemon-"),
            capacityProviderArns=[cp_arn],
            daemonTaskDefinitionArn=dtd_arn,
            tags=_ECS_TAGS,
        )
        daemon_arn = daemon["daemonArn"]
        ctx.on_cleanup(lambda: ecs.delete_daemon(daemonArn=daemon_arn))
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"daemon setup not exercisable here: {exc}") from None

    # Positive control: DescribeDaemon on the real daemon succeeds, so the negatives below
    # cannot pass by rejecting everything.
    real_describe = ecs.describe_daemon(daemonArn=daemon_arn)["daemon"]
    assert real_describe["daemonArn"] == daemon_arn, (
        f"DescribeDaemon positive control: expected {daemon_arn}, got {real_describe.get('daemonArn')}"
    )

    bogus_cluster = ctx.unique_name("no-such-cluster-")
    bogus_cluster_arn = f"arn:aws:ecs:{ctx.region}:{account_id}:cluster/{bogus_cluster}"
    bogus_daemon_arn = _swap_cluster_in_arn(daemon_arn, cluster_name, bogus_cluster)

    code, message = _error(
        lambda: ecs.create_daemon(
            clusterArn=bogus_cluster_arn,
            daemonName=ctx.unique_name("daemon-"),
            capacityProviderArns=[cp_arn],
            daemonTaskDefinitionArn=dtd_arn,
        )
    )
    assert code == "ClusterNotFoundException", f"CreateDaemon: got {code}"
    assert message == "Cluster not found.", f"CreateDaemon message: got {message!r}"

    code, message = _error(lambda: ecs.delete_daemon(daemonArn=bogus_daemon_arn))
    assert code == "ClusterNotFoundException", f"DeleteDaemon: got {code}"
    assert message == "Cluster not found.", f"DeleteDaemon message: got {message!r}"

    code, message = _error(lambda: ecs.describe_daemon(daemonArn=bogus_daemon_arn))
    assert code == "DaemonNotFoundException", f"DescribeDaemon: got {code}"
    assert message == f"Daemon not found: {bogus_daemon_arn}", f"DescribeDaemon message: got {message!r}"

    code, message = _error(
        lambda: ecs.update_daemon(
            daemonArn=bogus_daemon_arn,
            capacityProviderArns=[cp_arn],
            daemonTaskDefinitionArn=dtd_arn,
        )
    )
    assert code == "ClusterNotFoundException", f"UpdateDaemon: got {code}"
    assert message == "Cluster not found.", f"UpdateDaemon message: got {message!r}"

    resp = ecs.list_daemons(clusterArn=bogus_cluster_arn)
    assert resp["daemonSummariesList"] == [], f"ListDaemons: expected empty, got {resp['daemonSummariesList']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
