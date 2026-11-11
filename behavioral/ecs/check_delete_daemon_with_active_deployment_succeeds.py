"""delete-daemon-with-active-deployment-succeeds."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-daemon-with-active-deployment-succeeds"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDaemon on a daemon whose rollout deployment is still PENDING/IN_PROGRESS
    succeeds immediately: real AWS applies no state-conflict gate tied to deployment
    status and DeleteDaemon has no `force` parameter to bypass one.
    """
    ecs = ctx.client("ecs")
    iam = ctx.client("iam")

    cluster_name = ctx.unique_name("sim2real-daemon-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": CHECK}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _teardown(lambda: ecs.delete_cluster(cluster=cluster_arn)))

    try:
        infra_role_arn = _create_infra_role(ctx, iam)
        instance_profile_arn = _create_instance_profile(ctx, iam)
        subnet_id, sg_id = _default_subnet_and_sg(ctx)

        cp_name = ctx.unique_name("sim2real-daemon-cp-")

        def _try_create_cp():
            try:
                return ecs.create_capacity_provider(
                    name=cp_name,
                    cluster=cluster_name,
                    managedInstancesProvider={
                        "infrastructureRoleArn": infra_role_arn,
                        "instanceLaunchTemplate": {
                            "ec2InstanceProfileArn": instance_profile_arn,
                            "networkConfiguration": {"subnets": [subnet_id], "securityGroups": [sg_id]},
                            "instanceRequirements": {"vCpuCount": {"min": 1, "max": 2}, "memoryMiB": {"min": 512}},
                        },
                    },
                    tags=[{"key": "sim2real", "value": CHECK}],
                )["capacityProvider"]
            except Exception as exc:  # noqa: BLE001 - IAM propagation lag surfaces as a ClientError
                return exc

        cp = _poll_until(
            _try_create_cp,
            lambda r: not isinstance(r, Exception),
            timeout_s=90.0,
            interval_s=10.0,
        )
        if isinstance(cp, Exception):
            raise cp
        cp_arn = cp["capacityProviderArn"]
        ctx.on_cleanup(lambda: _teardown(lambda: _delete_capacity_provider_and_wait(ecs, cp_arn)))
    except Exception as exc:  # noqa: BLE001 - genuinely optional preview-feature prerequisite
        raise AssertionError(
            f"unreachable: ECS Managed Instances capacity provider prerequisites not satisfiable "
            f"in this account/region ({type(exc).__name__}: {exc})"
        ) from exc

    cp_status = _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_arn])["capacityProviders"][0]["status"],
        lambda s: s in ("ACTIVE", "UPDATE_FAILED"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    if cp_status != "ACTIVE":
        raise AssertionError(
            f"unreachable: managed instances capacity provider never reached ACTIVE ({cp_status})",
        )

    td_family = ctx.unique_name("sim2real-daemon-td")
    try:
        daemon_td_arn = ecs.register_daemon_task_definition(
            family=td_family,
            containerDefinitions=[
                {
                    "name": "agent",
                    "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                    "essential": True,
                    "command": ["sleep", "300"],
                    "memory": 128,
                }
            ],
            tags=[{"key": "sim2real", "value": CHECK}],
        )["daemonTaskDefinitionArn"]
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"unreachable: RegisterDaemonTaskDefinition not usable here ({exc})") from exc
    ctx.on_cleanup(
        lambda: _teardown(lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition=daemon_td_arn))
    )

    daemon_name = ctx.unique_name("sim2real-daemon-")
    try:
        created = ecs.create_daemon(
            daemonName=daemon_name,
            clusterArn=cluster_arn,
            daemonTaskDefinitionArn=daemon_td_arn,
            capacityProviderArns=[cp_arn],
            tags=[{"key": "sim2real", "value": CHECK}],
        )
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"unreachable: CreateDaemon not usable in this account/region ({exc})") from exc
    daemon_arn = created["daemonArn"]
    ctx.on_cleanup(lambda: _teardown(lambda: ecs.delete_daemon(daemonArn=daemon_arn)))
    deployment_arn = created.get("deploymentArn")
    assert created["status"] == "ACTIVE", f"unexpected initial daemon status: {created['status']}"

    # --- DeleteDaemon while the initial rollout is still in flight: measured against real
    # AWS, this succeeds immediately -- DeleteDaemon has no `force` parameter and applies no
    # state-conflict gate tied to deployment status.
    dep_status = None
    if deployment_arn:
        dep_status = ecs.describe_daemon_deployments(daemonDeploymentArns=[deployment_arn])[
            "daemonDeployments"
        ][0]["status"]

    if dep_status not in ("PENDING", "IN_PROGRESS"):
        raise AssertionError(
            f"unreachable: daemon deployment reached terminal state ({dep_status}) before it could be observed IN_PROGRESS"
        )

    deleted = ecs.delete_daemon(daemonArn=daemon_arn)
    assert deleted["status"] == "DELETE_IN_PROGRESS", (
        f"unexpected status deleting a daemon with an in-progress deployment: {deleted['status']}"
    )

    # independent read at a DIFFERENT operation than the mutation: DeleteDaemon actually
    # removes the daemon rather than merely marking it inactive -- describe eventually
    # reports the specific not-found code, not a lingering terminal status.
    def _probe_gone():
        try:
            return ecs.describe_daemon(daemonArn=daemon_arn)["daemon"]["status"]
        except ClientError as exc:
            return exc.response["Error"]["Code"]

    final = _poll_until(
        _probe_gone,
        lambda r: r != "DELETE_IN_PROGRESS",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final == "DaemonNotFoundException", (
        f"expected the daemon to fully disappear after DeleteDaemon, got {final}"
    )

    # a further mutation on the now-dead id also fails, with the same specific code
    try:
        ecs.update_daemon(
            daemonArn=daemon_arn, daemonTaskDefinitionArn=daemon_td_arn, capacityProviderArns=[cp_arn]
        )
        raise AssertionError("UpdateDaemon unexpectedly succeeded against a deleted daemon")
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "InvalidParameterException", (
            f"expected InvalidParameterException updating a deleted daemon, got {exc.response['Error']['Code']}"
        )
        assert exc.response["Error"]["Message"] == "Daemon service not found", (
            f'expected the exact InvalidParameterException message AWS returns, got {exc.response["Error"]["Message"]!r}'
        )


# ===== helpers =====

_MISSING_CODES = {"ClusterNotFoundException", "DaemonNotFoundException", "NoSuchEntity", "ResourceNotFoundException"}
_IN_USE_CODES = {
    "ClusterContainsCapacityProviderException",
    "ClusterContainsServicesException",
    "ClusterContainsTasksException",
    "ClusterContainsContainerInstancesException",
    "ResourceInUseException",
    "UpdateInProgressException",
    "DeleteConflict",
}


def _teardown(fn, timeout_s: float = 120.0) -> None:
    """Run a teardown step: return once it succeeds or its target is already gone, retry while a
    dependency is still being released, raise anything else."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code in _MISSING_CODES or (code == "InvalidParameterException" and "not found" in message.lower()):
                return
            if code not in _IN_USE_CODES or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    return result


def _delete_capacity_provider_and_wait(ecs, cp_arn) -> None:
    """Delete the capacity provider and wait for it to clear the cluster.

    DeleteCluster documents ClusterContainsCapacityProviderException while a capacity
    provider is still associated, so the cluster delete that follows (LIFO) would
    otherwise fail on an attached-but-deprovisioning provider.
    """
    try:
        ecs.delete_capacity_provider(capacityProvider=cp_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise
        return
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        state = ecs.describe_capacity_providers(capacityProviders=[cp_arn])["capacityProviders"]
        if not state or state[0]["status"] == "INACTIVE":
            return
        time.sleep(2.0)
    raise RuntimeError(f"capacity provider {cp_arn} not INACTIVE within 300s of DeleteCapacityProvider")


def _default_subnet_and_sg(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available for managed-instances networkConfiguration")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group available")
    return subnets[0]["SubnetId"], sgs[0]["GroupId"]


def _create_infra_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-ecs-infra-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _teardown(lambda: iam.delete_role(RoleName=role_name)))
    try:
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSInfrastructureRolePolicyForManagedInstances",
        )
        ctx.on_cleanup(
            lambda: _teardown(
                lambda: iam.detach_role_policy(
                    RoleName=role_name,
                    PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSInfrastructureRolePolicyForManagedInstances",
                )
            )
        )
    except Exception:
        # fall back to a broad inline policy if the managed policy name/shape has changed
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="ecs-managed-instances-infra",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": ["ec2:*", "iam:PassRole"], "Resource": "*"}],
                }
            ),
        )
        ctx.on_cleanup(
            lambda: _teardown(
                lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="ecs-managed-instances-infra")
            )
        )
    return role_arn


def _create_instance_profile(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-ecs-ec2-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown(lambda: iam.delete_role(RoleName=role_name)))
    try:
        iam.attach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
        )
        ctx.on_cleanup(
            lambda: _teardown(
                lambda: iam.detach_role_policy(
                    RoleName=role_name,
                    PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role",
                )
            )
        )
    except Exception:
        pass

    profile_name = ctx.unique_name("sim2real-ecs-profile-")
    profile_arn = iam.create_instance_profile(
        InstanceProfileName=profile_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["InstanceProfile"]["Arn"]
    ctx.on_cleanup(lambda: _teardown(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
        )
    )
    return profile_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
