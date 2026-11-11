"""daemon-deployment-tracking."""
from __future__ import annotations

import json
import time
import uuid

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "daemon-deployment-tracking"
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
    """CreateDaemon and UpdateDaemon each produce a daemon deployment that reaches a terminal
    status, retrievable by ARN via DescribeDaemonDeployments and by daemonArn via
    ListDaemonDeployments."""
    ecs = ctx.client("ecs")
    infra = _setup_managed_instances_capacity_provider(ctx)
    family = ctx.unique_name("sim2real-daemon-td-")
    td_v1 = _register_daemon_task_def(ctx, family, memory=128)
    td_v2 = _register_daemon_task_def(ctx, family, memory=256)

    created = ecs.create_daemon(
        daemonName=ctx.unique_name("sim2real-daemon-"),
        clusterArn=infra["cluster_arn"],
        daemonTaskDefinitionArn=td_v1,
        capacityProviderArns=[infra["capacity_provider_arn"]],
    )
    daemon_arn = created["daemonArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_daemon(daemonArn=daemon_arn)))
    initial_deployment_arn = created["deploymentArn"]

    initial = _poll_until(
        lambda: ecs.describe_daemon_deployments(daemonDeploymentArns=[initial_deployment_arn])["daemonDeployments"][0],
        lambda d: d["status"] in _TERMINAL_STATUSES,
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert initial["status"] == "SUCCESSFUL", (
        f"initial daemon deployment should reach SUCCESSFUL, got status={initial['status']!r}"
    )
    assert initial["clusterArn"] == infra["cluster_arn"]
    assert initial["targetDaemonRevision"]["arn"], "initial deployment should reference a target daemon revision"

    updated = ecs.update_daemon(
        daemonArn=daemon_arn,
        daemonTaskDefinitionArn=td_v2,
        capacityProviderArns=[infra["capacity_provider_arn"]],
    )
    second_deployment_arn = updated["deploymentArn"]
    assert second_deployment_arn != initial_deployment_arn

    second = _poll_until(
        lambda: ecs.describe_daemon_deployments(daemonDeploymentArns=[second_deployment_arn])["daemonDeployments"][0],
        lambda d: d["status"] in _TERMINAL_STATUSES,
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert second["status"] == "SUCCESSFUL", (
        f"second daemon deployment should reach SUCCESSFUL, got status={second['status']!r}"
    )
    assert second["targetDaemonRevision"]["arn"] != initial["targetDaemonRevision"]["arn"], (
        "the second deployment should target a different daemon revision than the first"
    )

    listed = ecs.list_daemon_deployments(daemonArn=daemon_arn)["daemonDeployments"]
    listed_arns = {d["daemonDeploymentArn"] for d in listed}
    assert {initial_deployment_arn, second_deployment_arn} <= listed_arns, (
        f"ListDaemonDeployments should surface both deployments, got {listed_arns}"
    )
    for entry in listed:
        if entry["daemonDeploymentArn"] in (initial_deployment_arn, second_deployment_arn):
            assert entry["daemonArn"] == daemon_arn


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
    )["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition=arn)))
    return arn


def _setup_managed_instances_capacity_provider(ctx) -> dict:
    """Provision the IAM roles, cluster, and Managed Instances capacity
    provider that ECS Managed Daemons require. Registers teardown for every
    resource it creates and raises AssertionError (never silently skips) if
    the account/region can't satisfy the prerequisites."""

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

        # ECS assumes infra_role_arn to provision the capacity provider, and a role that was just
        # created (and just had a policy attached) is not always immediately assumable by another
        # service — IAM's cross-service trust propagation lags the control-plane write that made
        # get_role start succeeding. AWS surfaces that lag here as a CREATE_FAILED capacity provider
        # with a ServiceAccessDeniedException reason rather than a synchronous CreateCapacityProvider
        # error, so it has to be detected async and retried with a *new* capacity provider, not
        # mistaken for a permanent rejection of this role/policy pair.
        cp_state = None
        last_reason = None
        for cp_attempt in range(4):
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
            ctx.on_cleanup(lambda cp_arn=cp_arn: _safe(lambda: _delete_capacity_provider_and_wait(ecs, cp_arn)))

            def _describe_cp():
                return ecs.describe_capacity_providers(capacityProviders=[cp_arn])["capacityProviders"][0]

            cp_state = _poll_until(_describe_cp, lambda cp_: cp_["status"] != "PROVISIONING", timeout_s=150.0, interval_s=5.0)
            if cp_state["status"] == "ACTIVE":
                break
            last_reason = cp_state.get("updateStatusReason") or ""
            if "ServiceAccessDeniedException" not in last_reason and "AccessDenied" not in last_reason:
                raise _never_ready(
                    f"managed-instances capacity provider never reached ACTIVE "
                    f"(status={cp_state['status']}, updateStatus={cp_state.get('updateStatus')}, "
                    f"updateStatusReason={cp_state.get('updateStatusReason')})",
                )
            time.sleep(15.0 * (cp_attempt + 1))
        else:
            raise _never_ready(
                f"managed-instances capacity provider never reached ACTIVE after 4 attempts, "
                f"each rejected by IAM as the infrastructure role not yet assumable "
                f"(status={cp_state['status']}, updateStatusReason={last_reason})",
            )

        return {"cluster_arn": cluster_arn, "cluster_name": cluster_name, "capacity_provider_arn": cp_arn}
    except AssertionError:
        raise
    except Exception as err:  # pragma: no cover - defensive: any prereq failure just skips
        raise AssertionError(f"managed-instances prerequisite setup failed: {err}") from err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
