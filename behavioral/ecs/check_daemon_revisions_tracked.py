"""daemon-revisions-tracked."""
from __future__ import annotations

import json
import time
import uuid

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "daemon-revisions-tracked"
GROUP = "state-machine"
SERVICES = ["ecs"]

_INFRA_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonECSInfrastructureRolePolicyForManagedInstances"
_INSTANCE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"
_TERMINAL_STATUSES = {"SUCCESSFUL", "STOPPED", "ROLLBACK_SUCCESSFUL", "ROLLBACK_FAILED"}


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
    """A create and two updates produce three distinct, immutable daemon revisions, each
    retrievable via DescribeDaemonRevisions and pinned to the daemonTaskDefinitionArn and
    container image it was captured with."""
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
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    daemon_arn = created["daemonArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_daemon(daemonArn=daemon_arn)))

    deployment_arns = [created["deploymentArn"]]
    for td_arn in (td_v2, td_v3):
        updated = ecs.update_daemon(
            daemonArn=daemon_arn,
            daemonTaskDefinitionArn=td_arn,
            capacityProviderArns=[infra["capacity_provider_arn"]],
        )
        deployment_arns.append(updated["deploymentArn"])

    revision_arns = []
    expected_td_by_revision = {}
    for deployment_arn, expected_td in zip(deployment_arns, (td_v1, td_v2, td_v3)):
        deployment = _poll_until(
            lambda d=deployment_arn: ecs.describe_daemon_deployments(daemonDeploymentArns=[d])["daemonDeployments"][0],
            lambda d: d["status"] in _TERMINAL_STATUSES,
            timeout_s=120.0,
            interval_s=5.0,
        )
        revision_arn = deployment["targetDaemonRevision"]["arn"]
        revision_arns.append(revision_arn)
        expected_td_by_revision[revision_arn] = expected_td

    assert len(set(revision_arns)) == 3, f"expected 3 distinct daemon revisions, got {revision_arns}"

    described = ecs.describe_daemon_revisions(daemonRevisionArns=revision_arns)["daemonRevisions"]
    assert len(described) == 3, f"DescribeDaemonRevisions should resolve all 3 revisions, got {len(described)}"
    for revision in described:
        expected_td = expected_td_by_revision[revision["daemonRevisionArn"]]
        assert revision["daemonTaskDefinitionArn"] == expected_td, (
            f"revision {revision['daemonRevisionArn']} should pin daemonTaskDefinitionArn={expected_td}, "
            f"got {revision['daemonTaskDefinitionArn']}"
        )
        assert revision["daemonArn"] == daemon_arn, (
            f"revision {revision['daemonRevisionArn']} should belong to daemon {daemon_arn}, "
            f"got daemonArn={revision['daemonArn']}"
        )


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
        tags=[{"key": "sim2real-check", "value": CHECK}],
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
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=instance_role_name)))
        iam.attach_role_policy(RoleName=instance_role_name, PolicyArn=_INSTANCE_POLICY_ARN)
        ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=instance_role_name, PolicyArn=_INSTANCE_POLICY_ARN)))

        profile_name = instance_role_name
        iam.create_instance_profile(
            InstanceProfileName=profile_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
        )
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
        cluster_arn = ecs.create_cluster(
            clusterName=cluster_name, tags=[{"key": "sim2real-check", "value": CHECK}]
        )["cluster"]["clusterArn"]
        ctx.on_cleanup(lambda: _safe(lambda: _delete_cluster_retrying(ecs, cluster_arn)))

        cp_arn = None
        cp_state = None
        last_err = None
        # IAM role/policy propagation to the ECS control plane is eventually consistent even
        # after get_role above confirms the role exists: CreateCapacityProvider can accept the
        # request and then fail it asynchronously with ServiceAccessDeniedException for the
        # infra role. Retry with a fresh capacity provider name (ECS rejects name reuse of an
        # INACTIVE provider), at most 5 times and until a deadline, giving IAM time to catch up.
        attempts_deadline = time.monotonic() + 150.0
        for _attempt in (a for a in range(5) if time.monotonic() < attempts_deadline):
            cp_name = ctx.unique_name(f"sim2real-ecs-daemon-cp{_attempt}-")
            try:
                cp_arn = ecs.create_capacity_provider(
                    name=cp_name,
                    cluster=cluster_name,
                    managedInstancesProvider={
                        "infrastructureRoleArn": infra_role_arn,
                        "instanceLaunchTemplate": {
                            "ec2InstanceProfileArn": profile_arn,
                            "networkConfiguration": {"subnets": subnet_ids, "securityGroups": [sg_id]},
                        },
                    },
                    tags=[{"key": "sim2real-check", "value": CHECK}],
                )["capacityProvider"]["capacityProviderArn"]
            except botocore.exceptions.ClientError as err:
                last_err = err
                time.sleep(2.0)
                continue
            ctx.on_cleanup(lambda arn=cp_arn: _safe(lambda: _delete_capacity_provider_and_wait(ecs, arn)))

            def _describe_cp(arn=cp_arn):
                return ecs.describe_capacity_providers(capacityProviders=[arn])["capacityProviders"][0]

            cp_state = _poll_until(_describe_cp, lambda cp_: cp_["status"] != "PROVISIONING", timeout_s=150.0, interval_s=5.0)
            if cp_state["status"] == "ACTIVE":
                break
            reason = cp_state.get("updateStatusReason") or ""
            if "ServiceAccessDeniedException" in reason and "ECSInfrastructureRole" in reason:
                last_err = reason
                time.sleep(2.0)
                continue
            raise _never_ready(
                f"managed-instances capacity provider never reached ACTIVE "
                f"(status={cp_state['status']}, updateStatus={cp_state.get('updateStatus')}, "
                f"updateStatusReason={cp_state.get('updateStatusReason')})",
            )
        else:
            raise AssertionError(
                f"could not create managed-instances capacity provider after 5 attempts within 150 s "
                f"retrying IAM propagation of the infrastructure role; last state={cp_state}, last_err={last_err}"
            )

        return {"cluster_arn": cluster_arn, "cluster_name": cluster_name, "capacity_provider_arn": cp_arn}
    except AssertionError:
        raise
    except Exception as err:  # pragma: no cover - defensive: any prereq failure just skips
        raise AssertionError(f"managed-instances prerequisite setup failed: {err}") from err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
