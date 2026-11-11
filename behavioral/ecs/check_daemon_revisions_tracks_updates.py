"""daemon-revisions-tracks-updates."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "daemon-revisions-tracks-updates"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDaemon on an existing daemon creates a new revision (new daemonTaskDefinitionArn)
    that's visible via DescribeDaemonRevisions, distinct from the original revision."""

    ecs = ctx.client("ecs")
    infra = _setup_daemon_infra(ctx)
    cluster_arn, cp_arn = infra["cluster_arn"], infra["cp_arn"]
    task_def_v1 = _register_daemon_task_definition(ctx, sleep_seconds=3600)

    daemon_name = ctx.unique_name("sim2real-daemon-")
    try:
        created = ecs.create_daemon(
            daemonName=daemon_name,
            daemonTaskDefinitionArn=task_def_v1,
            capacityProviderArns=[cp_arn],
            clusterArn=cluster_arn,
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "UnsupportedFeatureException":
            raise AssertionError(f"unreachable: CreateDaemon unsupported here: {e}")
        raise
    daemon_arn = created["daemonArn"]
    ctx.on_cleanup(lambda: _safe_delete_daemon(ecs, daemon_arn))

    daemon = _poll_until(
        lambda: ecs.describe_daemon(daemonArn=daemon_arn)["daemon"],
        lambda d: d["status"] == "ACTIVE" and d.get("currentRevisions"),
        timeout_s=180,
        interval_s=5,
    )
    original_revision_arn = daemon["currentRevisions"][0]["arn"]
    original_desc = ecs.describe_daemon_revisions(daemonRevisionArns=[original_revision_arn])["daemonRevisions"][0]
    assert original_desc["daemonTaskDefinitionArn"] == task_def_v1

    # register a second daemon task definition revision and update the daemon to use it
    task_def_v2 = _register_daemon_task_definition(ctx, sleep_seconds=7200)
    ecs.update_daemon(
        daemonArn=daemon_arn,
        daemonTaskDefinitionArn=task_def_v2,
        capacityProviderArns=[cp_arn],
    )

    updated_daemon = _poll_until(
        lambda: ecs.describe_daemon(daemonArn=daemon_arn)["daemon"],
        lambda d: d["status"] == "ACTIVE"
        and d.get("currentRevisions")
        and d["currentRevisions"][0]["arn"] != original_revision_arn,
        timeout_s=180,
        interval_s=5,
    )
    new_revision_arn = updated_daemon["currentRevisions"][0]["arn"]
    assert new_revision_arn != original_revision_arn

    new_desc = ecs.describe_daemon_revisions(daemonRevisionArns=[new_revision_arn])["daemonRevisions"][0]
    assert new_desc["daemonTaskDefinitionArn"] == task_def_v2

    # both revisions remain independently describable (revisions are immutable snapshots)
    both = ecs.describe_daemon_revisions(daemonRevisionArns=[original_revision_arn, new_revision_arn])["daemonRevisions"]
    arns_seen = {r["daemonRevisionArn"] for r in both}
    assert original_revision_arn in arns_seen and new_revision_arn in arns_seen


# ===== helpers =====
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
    """Delete the daemon task definition; one that no longer exists is done, any other error raises."""
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

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("unreachable: no shared network VPC available for ECS Managed Instances")
    vpc_id = vpcs[0]["VpcId"]
    subnets = [
        s["SubnetId"]
        for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    ][:2]
    if not subnets:
        raise AssertionError("unreachable: shared network has no subnets")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("unreachable: shared network has no default security group")
    sg_id = sgs[0]["GroupId"]

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

        iam.create_role(RoleName=instance_role_name, AssumeRolePolicyDocument=instance_trust)["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=instance_role_name))
        instance_policy_arn = "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"
        iam.attach_role_policy(RoleName=instance_role_name, PolicyArn=instance_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=instance_role_name, PolicyArn=instance_policy_arn))

        iam.create_instance_profile(InstanceProfileName=instance_role_name)
        ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=instance_role_name))
        iam.add_role_to_instance_profile(InstanceProfileName=instance_role_name, RoleName=instance_role_name)
        ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=instance_role_name, RoleName=instance_role_name))
    except ClientError as e:
        raise AssertionError(f"unreachable: cannot provision IAM roles for ECS Managed Instances: {e}")

    account_id = sts.get_caller_identity()["Account"]
    profile_arn = f"arn:aws:iam::{account_id}:instance-profile/{instance_role_name}"

    cluster_name = ctx.unique_name("sim2real-ecs-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_detached(ecs, cluster_arn))

    # ECS assumes the just-created infrastructure role to provision the Managed
    # Instances fleet. A freshly created role's trust/attached policies are not
    # immediately usable (IAM eventual consistency), so a capacity provider created
    # too soon settles to CREATE_FAILED ("ServiceAccessDeniedException for
    # ECSInfrastructureRole"). Create and wait for the async provision to settle; if it
    # fails on role access, recreate with a fresh name over a generous budget.
    def _create_once():
        cp_name = ctx.unique_name("sim2real-mi-cp-")
        create_deadline = time.monotonic() + 90
        while True:
            try:
                ecs.create_capacity_provider(
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
                )
                break
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "UnsupportedFeatureException":
                    raise AssertionError(f"unreachable: ECS Managed Instances unsupported here: {e}")
                if time.monotonic() >= create_deadline:
                    raise AssertionError(f"could not provision a Managed Instances capacity provider: {e}") from None
                time.sleep(2)
        ctx.on_cleanup(lambda: _delete_capacity_provider_and_wait(ecs, cp_name))
        settle_deadline = time.monotonic() + 180
        while True:
            # DescribeCapacityProviders is eventually consistent right after
            # CreateCapacityProvider — the provider can be briefly absent, so
            # tolerate an empty list instead of indexing [0] and keep polling.
            cps = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"]
            cp = cps[0] if cps else {}
            if cp.get("status") == "ACTIVE":
                return cp["capacityProviderArn"], True
            if cp.get("updateStatus") == "CREATE_FAILED" or cp.get("status") == "INACTIVE":
                return cp_name, False
            if time.monotonic() >= settle_deadline:
                return cp_name, False
            time.sleep(2)

    attempts_deadline = time.monotonic() + 210
    cp_arn, ok = _create_once()
    while not ok:
        if time.monotonic() >= attempts_deadline:
            raise AssertionError(
                "Managed Instances capacity provider repeatedly settled to CREATE_FAILED "
                "(infrastructure-role access); not exercisable in this account"
            )
        time.sleep(2)
        cp_arn, ok = _create_once()

    return {"cluster_arn": cluster_arn, "cp_arn": cp_arn}


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
