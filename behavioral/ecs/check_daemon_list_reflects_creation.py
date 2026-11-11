"""daemon-list-reflects-creation."""
from __future__ import annotations

import json
import time
import uuid

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "daemon-list-reflects-creation"
GROUP = "state-machine"
SERVICES = ["ecs"]

_INFRA_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonECSInfrastructureRolePolicyForManagedInstances"
_INSTANCE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"

_TAGS = [
    {"key": "sim2real:managed", "value": "true"},
    {"key": "sim2real:prefix", "value": "sim2real-daemon"},
]
_IAM_TAGS = [{"Key": t["key"], "Value": t["value"]} for t in _TAGS]


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
    """ListDaemons (scoped to the daemon's cluster) includes the daemonArn
    immediately after CreateDaemon and excludes it again once DeleteDaemon has
    finished removing it."""
    ecs = ctx.client("ecs")
    infra = _setup_managed_instances_capacity_provider(ctx)
    td_arn = _register_daemon_task_def(ctx, ctx.unique_name("sim2real-daemon-td-"))

    created = ecs.create_daemon(
        daemonName=ctx.unique_name("sim2real-daemon-"),
        clusterArn=infra["cluster_arn"],
        daemonTaskDefinitionArn=td_arn,
        capacityProviderArns=[infra["capacity_provider_arn"]],
        tags=_TAGS,
    )
    daemon_arn = created["daemonArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_daemon(daemonArn=daemon_arn)))

    def _list_arns():
        return {
            d["daemonArn"]
            for d in ecs.list_daemons(clusterArn=infra["cluster_arn"])["daemonSummariesList"]
        }

    present = _poll_until(_list_arns, lambda arns: daemon_arn in arns, timeout_s=30.0, interval_s=2.0)
    assert daemon_arn in present, "ListDaemons did not surface the daemon right after creation"

    ecs.delete_daemon(daemonArn=daemon_arn)

    absent = _poll_until(_list_arns, lambda arns: daemon_arn not in arns, timeout_s=120.0, interval_s=5.0)
    assert daemon_arn not in absent, "ListDaemons still returned the daemon after deletion finished"

    dead_delete_code, _ = _error(lambda: ecs.delete_daemon(daemonArn=daemon_arn))
    assert dead_delete_code == "DaemonNotFoundException", (
        f"DeleteDaemon on an already-deleted daemonArn returned {dead_delete_code!r}, "
        "expected DaemonNotFoundException"
    )
    # message varies: "No daemon metadata found." or "Daemon service not found: <arn>", depending on how far
    # the asynchronous delete has progressed when this DeleteDaemon lands


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


def _error(fn):
    """The error code and message of a call that must be rejected; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
        tags=_TAGS,
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
            Tags=_IAM_TAGS,
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
            Tags=_IAM_TAGS,
        )
        ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=instance_role_name)))
        iam.attach_role_policy(RoleName=instance_role_name, PolicyArn=_INSTANCE_POLICY_ARN)
        ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=instance_role_name, PolicyArn=_INSTANCE_POLICY_ARN)))

        profile_name = instance_role_name
        iam.create_instance_profile(InstanceProfileName=profile_name, Tags=_IAM_TAGS)
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
        cluster_arn = ecs.create_cluster(clusterName=cluster_name, tags=_TAGS)["cluster"]["clusterArn"]
        ctx.on_cleanup(lambda: _safe(lambda: _delete_cluster_retrying(ecs, cluster_arn)))

        def _create_and_settle():
            """One attempt: create a freshly-named CP, then wait up to 180s for it to
            leave PROVISIONING. Returns the terminal describe_capacity_providers state.

            ECS assumes the just-created infrastructure role to provision the Managed
            Instances fleet, and a freshly created role's trust/attached policies are
            not immediately usable (IAM eventual consistency) — a CP created too soon
            settles to CREATE_FAILED ("ServiceAccessDeniedException for
            ECSInfrastructureRole"), never ACTIVE. A fresh name is required per retry:
            ECS never resurrects a CP that already settled to CREATE_FAILED/INACTIVE.
            """
            attempt_cp_name = ctx.unique_name("sim2real-ecs-daemon-cp-")
            attempt_arn = ecs.create_capacity_provider(
                name=attempt_cp_name,
                cluster=cluster_name,
                managedInstancesProvider={
                    "infrastructureRoleArn": infra_role_arn,
                    "instanceLaunchTemplate": {
                        "ec2InstanceProfileArn": profile_arn,
                        "networkConfiguration": {"subnets": subnet_ids, "securityGroups": [sg_id]},
                    },
                },
                tags=_TAGS,
            )["capacityProvider"]["capacityProviderArn"]
            ctx.on_cleanup(lambda: _safe(lambda: _delete_capacity_provider_and_wait(ecs, attempt_arn)))

            def _describe_cp():
                return ecs.describe_capacity_providers(capacityProviders=[attempt_arn])["capacityProviders"][0]

            return _poll_until(_describe_cp, lambda cp_: cp_["status"] != "PROVISIONING", timeout_s=180.0, interval_s=10.0)

        attempts_deadline = time.monotonic() + 210.0
        cp_state = _create_and_settle()
        while cp_state["status"] != "ACTIVE":
            if time.monotonic() >= attempts_deadline:
                raise _never_ready(
                    "managed-instances capacity provider repeatedly settled to non-ACTIVE "
                    f"(status={cp_state['status']}, updateStatus={cp_state.get('updateStatus')}, "
                    f"updateStatusReason={cp_state.get('updateStatusReason')!r})",
                )
            time.sleep(2.0)
            cp_state = _create_and_settle()

        return {
            "cluster_arn": cluster_arn,
            "cluster_name": cluster_name,
            "capacity_provider_arn": cp_state["capacityProviderArn"],
        }
    except AssertionError:
        raise
    except Exception as err:  # pragma: no cover - defensive: any prereq failure fails the check
        raise AssertionError(f"managed-instances prerequisite setup failed: {err}") from err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
