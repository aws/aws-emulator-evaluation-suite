"""daemon-update-changes-desired-state."""
from __future__ import annotations

import json
import time
import uuid

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "daemon-update-changes-desired-state"
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
    """UpdateDaemon to a new daemon task definition revision yields a deployment whose
    targetDaemonRevision resolves to the new daemonTaskDefinitionArn, so the desired state
    changed rather than the request being echoed."""
    ecs = ctx.client("ecs")
    infra = _setup_managed_instances_capacity_provider(ctx)
    family = ctx.unique_name("sim2real-daemon-td-")
    td_v1 = _register_daemon_task_def(ctx, family, memory=128)
    td_v2 = _register_daemon_task_def(ctx, family, memory=256, command=["sleep", "7200"])

    created = ecs.create_daemon(
        daemonName=ctx.unique_name("sim2real-daemon-"),
        clusterArn=infra["cluster_arn"],
        daemonTaskDefinitionArn=td_v1,
        capacityProviderArns=[infra["capacity_provider_arn"]],
    )
    daemon_arn = created["daemonArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_daemon(daemonArn=daemon_arn)))

    updated = ecs.update_daemon(
        daemonArn=daemon_arn,
        daemonTaskDefinitionArn=td_v2,
        capacityProviderArns=[infra["capacity_provider_arn"]],
    )
    assert updated["status"] == "ACTIVE", f"expected ACTIVE after update, got {updated['status']}"
    new_deployment_arn = updated["deploymentArn"]
    assert new_deployment_arn != created["deploymentArn"], "UpdateDaemon should trigger a new, distinct deployment"

    deployment = ecs.describe_daemon_deployments(daemonDeploymentArns=[new_deployment_arn])["daemonDeployments"][0]
    target_revision_arn = deployment["targetDaemonRevision"]["arn"]

    revision = ecs.describe_daemon_revisions(daemonRevisionArns=[target_revision_arn])["daemonRevisions"][0]
    assert revision["daemonTaskDefinitionArn"] == td_v2, (
        "the daemon's new deployment should target the updated task definition revision, "
        f"got {revision['daemonTaskDefinitionArn']!r} instead of {td_v2!r}"
    )

    described = ecs.describe_daemon(daemonArn=daemon_arn)["daemon"]
    assert described["deploymentArn"] == new_deployment_arn, "DescribeDaemon should reflect the latest deployment"


# ===== helpers =====
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


def _succeeds(fn) -> bool:
    """True when fn() returns, False when it raises a ClientError (a readiness probe)."""
    try:
        fn()
    except botocore.exceptions.ClientError:
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
    """Provision the IAM roles, cluster, and Managed Instances capacity
    provider that ECS Managed Daemons require. Registers teardown for every
    resource it creates and raises AssertionError -- never skips -- if the
    account/region can't satisfy the prerequisites."""

    ecs = ctx.client("ecs")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    if not hasattr(ecs, "create_daemon"):
        raise AssertionError("installed botocore/boto3 has no ECS Managed Daemons operations")
    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
        if not vpcs:
            raise AssertionError("no shared network VPC available for managed-instances network configuration")
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        if not subnets:
            raise AssertionError("shared network has no subnets")
        subnet_ids = [s["SubnetId"] for s in subnets[:2]]
        sgs = ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
        )["SecurityGroups"]
        if not sgs:
            raise AssertionError("shared network has no default security group")
        sg_id = sgs[0]["GroupId"]

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
            lambda: _succeeds(lambda: iam.get_role(RoleName=infra_role_name)),
            lambda ready: ready,
            timeout_s=30.0,
            interval_s=2.0,
        )

        cluster_name = ctx.unique_name("sim2real-ecs-daemon-cl-")
        cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
        ctx.on_cleanup(lambda: _safe(lambda: _delete_cluster_retrying(ecs, cluster_arn)))

        # A freshly created infrastructure role is not immediately usable (IAM eventual
        # consistency), so a capacity provider created too soon settles to CREATE_FAILED /
        # INACTIVE ("ServiceAccessDeniedException for ECSInfrastructureRole") rather than
        # ACTIVE. Retry with a fresh capacity-provider name until a deadline.
        def _create_cp_once():
            cp_name = ctx.unique_name("sim2real-ecs-daemon-cp-")
            cp_kwargs = dict(
                name=cp_name,
                cluster=cluster_name,
                managedInstancesProvider={
                    "infrastructureRoleArn": infra_role_arn,
                    "instanceLaunchTemplate": {
                        "ec2InstanceProfileArn": profile_arn,
                        "networkConfiguration": {"subnets": subnet_ids, "securityGroups": [sg_id]},
                    },
                },
            )
            create_deadline = time.monotonic() + 90.0
            cp_arn = None
            last_err = None
            while cp_arn is None:
                try:
                    cp_arn = ecs.create_capacity_provider(**cp_kwargs)["capacityProvider"]["capacityProviderArn"]
                except botocore.exceptions.ClientError as err:
                    last_err = err
                    if time.monotonic() >= create_deadline:
                        raise AssertionError(f"could not create managed-instances capacity provider: {last_err}") from err
                    time.sleep(2.0)
            ctx.on_cleanup(lambda: _safe(lambda: _delete_capacity_provider_and_wait(ecs, cp_arn)))

            def _describe_cp():
                found = ecs.describe_capacity_providers(capacityProviders=[cp_arn])["capacityProviders"]
                return found[0] if found else {}

            settle_deadline = time.monotonic() + 150.0
            while True:
                cp_state = _describe_cp()
                if cp_state.get("status") == "ACTIVE":
                    return cp_arn, True
                if cp_state.get("updateStatus") == "CREATE_FAILED" or cp_state.get("status") == "INACTIVE":
                    return cp_arn, False
                if time.monotonic() >= settle_deadline:
                    return cp_arn, False
                time.sleep(5.0)

        attempts_deadline = time.monotonic() + 210.0
        cp_arn, ok = _create_cp_once()
        while not ok:
            if time.monotonic() >= attempts_deadline:
                raise _never_ready(
                    "managed-instances capacity provider repeatedly settled to CREATE_FAILED/INACTIVE "
                    "(infrastructure-role access) and never reached ACTIVE",
                )
            time.sleep(2.0)
            cp_arn, ok = _create_cp_once()

        return {"cluster_arn": cluster_arn, "cluster_name": cluster_name, "capacity_provider_arn": cp_arn}
    except AssertionError:
        raise
    except Exception as err:  # pragma: no cover - defensive: any prereq failure just skips
        raise AssertionError(f"managed-instances prerequisite setup failed: {err}") from err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
