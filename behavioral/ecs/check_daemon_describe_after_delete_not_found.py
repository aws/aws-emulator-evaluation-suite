"""daemon-describe-after-delete-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "daemon-describe-after-delete-not-found"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDaemon on a deleted daemon never shows stale ACTIVE and eventually 404s."""
    from botocore.exceptions import ClientError

    env = _setup_managed_instances_env(ctx)
    ecs = ctx.client("ecs")

    td_arn = _register_daemon_task_def(ctx)
    daemon_name = ctx.unique_name("sim2real-daemon-")
    daemon_arn = ecs.create_daemon(
        daemonName=daemon_name,
        clusterArn=env["cluster_arn"],
        daemonTaskDefinitionArn=td_arn,
        capacityProviderArns=[env["capacity_provider_arn"]],
        tags=[{"key": "sim2real:managed", "value": "true"}, {"key": "sim2real:check", "value": CHECK}],
    )["daemonArn"]
    ctx.on_cleanup(lambda: _delete_daemon_best_effort(ecs, daemon_arn))

    # positive control: while alive, describe reflects ACTIVE
    active_status = _poll_until(
        lambda: ecs.describe_daemon(daemonArn=daemon_arn)["daemon"]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=60.0,
    )
    assert active_status == "ACTIVE", f"positive control: expected ACTIVE before delete, got {active_status!r}"

    ecs.delete_daemon(daemonArn=daemon_arn)

    # immediately after delete, describe must not report stale ACTIVE
    try:
        immediate = ecs.describe_daemon(daemonArn=daemon_arn)["daemon"]["status"]
        assert immediate != "ACTIVE", f"describe reported stale ACTIVE right after delete: {immediate}"
    except ClientError as err:
        assert err.response["Error"]["Code"] == "DaemonNotFoundException", (
            f"expected DaemonNotFoundException right after delete, got {err.response['Error']['Code']!r}"
        )
        assert err.response["Error"].get("Message", "") == f"Daemon not found: {daemon_arn}", (
            f"expected the exact not-found message right after delete, got {err.response['Error'].get('Message')!r}"
        )

    # eventually the daemon is fully gone: describe fails with the specific not-found code
    def _describe_outcome():
        try:
            status = ecs.describe_daemon(daemonArn=daemon_arn)["daemon"]["status"]
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        return "DESCRIBED", status

    code, message = _poll_until(
        _describe_outcome, lambda o: o[0] == "DaemonNotFoundException", timeout_s=180.0, interval_s=5.0
    )
    assert code == "DaemonNotFoundException", f"expected DaemonNotFoundException, got {code!r}: {message!r}"
    assert message == f"Daemon not found: {daemon_arn}", f"expected the exact not-found message, got {message!r}"

    # a mutation on the now-fully-gone daemon fails with the same specific not-found code, not a
    # different one and not a silent no-op success
    try:
        ecs.delete_daemon(daemonArn=daemon_arn)
    except ClientError as err:
        second_delete_code = err.response["Error"]["Code"]
    else:
        raise AssertionError("DeleteDaemon on an already-deleted daemon unexpectedly succeeded")
    assert second_delete_code == "DaemonNotFoundException", (
        f"expected DaemonNotFoundException on delete of a gone daemon, got {second_delete_code!r}"
    )
    # message varies: "No daemon metadata found." or "Daemon service not found: <arn>", depending on how far
    # the asynchronous delete has progressed when the second DeleteDaemon lands


# ===== helpers =====

def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


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
        tags=[{"key": "sim2real:managed", "value": "true"}, {"key": "sim2real:check", "value": CHECK}],
    )
    arn = resp["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: _delete_daemon_task_def_best_effort(ecs, arn))
    return arn


def _delete_daemon_task_def_best_effort(ecs, arn):
    _retry_while(
        lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition=arn),
        {"ClientException", "ResourceInUseException", "UpdateInProgressException"},
        timeout_s=60,
    )


def _setup_managed_instances_env(ctx):
    """Provision the cluster + ECS Managed Instances capacity provider that ECS daemons require.

    Raises AssertionError (never skips) if the account/region cannot satisfy this prerequisite.
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

    iam_tags = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]

    try:
        infra_role_arn = iam.create_role(
            RoleName=infra_role_name, AssumeRolePolicyDocument=infra_trust, Tags=iam_tags
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=infra_role_name))
        iam.attach_role_policy(RoleName=infra_role_name, PolicyArn=infra_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=infra_role_name, PolicyArn=infra_policy_arn))

        iam.create_role(RoleName=instance_role_name, AssumeRolePolicyDocument=instance_trust, Tags=iam_tags)["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=instance_role_name))
        iam.attach_role_policy(RoleName=instance_role_name, PolicyArn=instance_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=instance_role_name, PolicyArn=instance_policy_arn))

        iam.create_instance_profile(InstanceProfileName=profile_name, Tags=iam_tags)
        ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
        iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=instance_role_name)
        ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=instance_role_name))
        profile_arn = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]["Arn"]
    except ClientError as err:
        raise AssertionError(
            f"unreachable: cannot provision IAM prerequisites for ECS Managed Instances ({err.response['Error']['Code']})"
        )

    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("unreachable: no shared network VPC subnets available for ECS Managed Instances network configuration")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    vpc_id = subnets[0]["VpcId"]
    default_sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not default_sgs:
        raise AssertionError("unreachable: no default security group available for ECS Managed Instances network configuration")
    sg_id = default_sgs[0]["GroupId"]

    ecs_tags = [{"key": "sim2real:managed", "value": "true"}, {"key": "sim2real:check", "value": CHECK}]

    cluster_name = ctx.unique_name("sim2real-daemon-cluster-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name, tags=ecs_tags)["cluster"]["clusterArn"]
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
                tags=ecs_tags,
            )
            cp_arn = resp["capacityProvider"]["capacityProviderArn"]
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            last_err = err
            if code in ("InvalidParameterException", "ClientException") and time.monotonic() < deadline - 5:
                time.sleep(5)
                continue
            raise AssertionError(
                f"unreachable: ECS Managed Instances capacity provider unavailable in this account/region "
                f"({code}: {message})"
            )
    if cp_arn is None:
        raise AssertionError(f"unreachable: could not create Managed Instances capacity provider: {last_err}")
    ctx.on_cleanup(lambda: _delete_capacity_provider_and_wait(ecs, cp_name))

    def _cp_status():
        d = ecs.describe_capacity_providers(capacityProviders=[cp_arn])["capacityProviders"]
        return d[0]["status"] if d else None

    try:
        status = _poll_until(_cp_status, lambda s: s == "ACTIVE", timeout_s=180.0, interval_s=5.0)
    except AssertionError as err:
        raise AssertionError(
            f"unreachable: Managed Instances capacity provider never reached ACTIVE ({err})",
        )
    assert status == "ACTIVE", f"expected the Managed Instances capacity provider ACTIVE, got {status!r}"

    return {"cluster_arn": cluster_arn, "cluster_name": cluster_name, "capacity_provider_arn": cp_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
