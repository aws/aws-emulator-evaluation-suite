"""daemon-deployment-new-revision-ordering."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "daemon-deployment-new-revision-ordering"
GROUP = 'daemon'
SERVICES = ['ecs']

_MI_INSTANCE_POLICY = "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"
_MI_INFRA_POLICY = "arn:aws:iam::aws:policy/AmazonECSInfrastructureRolePolicyForManagedInstances"

_DEFAULT_CONTAINER_DEF = {
    "name": "app",
    "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
    "cpu": 64,
    "memory": 128,
    "essential": True,
}


def _poll_until(fn, pred, *, timeout_s, interval_s=2, ctx=None):
    deadline = time.monotonic() + timeout_s
    while True:
        val = fn()
        if pred(val):
            return val
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(
                    "the daemon deployments listing: the run budget ended first; not graded")
            raise AssertionError(f"condition not met within {timeout_s}s (last={val!r})")
        time.sleep(interval_s)


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
        RoleName=instance_role, AssumeRolePolicyDocument=json.dumps(trust_ec2)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=instance_role))
    iam.attach_role_policy(RoleName=instance_role, PolicyArn=_MI_INSTANCE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=instance_role, PolicyArn=_MI_INSTANCE_POLICY))
    iam.create_instance_profile(InstanceProfileName=instance_role)
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
        RoleName=infra_role, AssumeRolePolicyDocument=json.dumps(trust_ecs)
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

    # ECS assumes the just-created infrastructure role to provision the Managed
    # Instances fleet. A freshly created role's trust/attached policies are not
    # immediately usable (IAM eventual consistency), so a CP created too soon
    # settles to CREATE_FAILED ("ServiceAccessDeniedException for
    # ECSInfrastructureRole") rather than ever reaching ACTIVE. Retry with a
    # fresh capacity provider name over a generous budget instead of waiting
    # out a single doomed attempt.
    def _create_once():
        cp_name = ctx.unique_name("cp-")
        create_deadline = time.monotonic() + 90
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
                )
                break
            except ClientError as exc:
                if time.monotonic() >= create_deadline:
                    raise AssertionError(
                        f"could not provision a Managed Instances capacity provider: {exc}"
                    ) from None
                time.sleep(2)
        ctx.on_cleanup(lambda: _delete_cp_and_wait(ecs, cp_name, cluster))
        settle_deadline = time.monotonic() + 180
        while True:
            cp = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0]
            if cp.get("status") == "ACTIVE":
                return cp_name, True
            if cp.get("updateStatus") == "CREATE_FAILED" or cp.get("status") == "INACTIVE":
                return cp_name, False
            if time.monotonic() >= settle_deadline:
                return cp_name, False
            time.sleep(2)

    attempts_deadline = time.monotonic() + 210
    cp_name, ok = _create_once()
    while not ok:
        if time.monotonic() >= attempts_deadline:
            raise AssertionError(
                "Managed Instances capacity provider repeatedly settled to CREATE_FAILED "
                "(infrastructure-role access); not exercisable in this account"
            )
        time.sleep(2)
        cp_name, ok = _create_once()
    return cp_name


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _register_daemon_td(ctx, ecs, family=None):
    arn = ecs.register_daemon_task_definition(
        family=family or ctx.unique_name("daemontd-"),
        containerDefinitions=[dict(_DEFAULT_CONTAINER_DEF)],
    )["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition=arn))
    return ecs.describe_daemon_task_definition(daemonTaskDefinition=arn)["daemonTaskDefinition"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDaemon to a new daemon task definition produces a new DaemonDeployment with a distinct
    target revision; ListDaemonDeployments and DescribeDaemonDeployments agree on every
    deployment's target, and DescribeDaemonRevisions maps the new revision to that task definition.
    """
    ecs = ctx.client("ecs")
    if not hasattr(ecs, "create_daemon"):
        raise AssertionError("client lacks ECS Managed Daemon operations")
    try:
        cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))["cluster"]
        cluster_name = cluster["clusterName"]
        ctx.on_cleanup(lambda: _delete_cluster_when_free(ecs, cluster_name))
        cp_name = _create_managed_instances_cp(ctx, ecs, cluster_name)
        cp_desc = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0]
        assert cp_desc["status"] == "ACTIVE", f"expected the capacity provider ACTIVE, got {cp_desc}"
        dtd1 = _register_daemon_td(ctx, ecs)
        created = ecs.create_daemon(
            daemonName=ctx.unique_name("daemon-"),
            clusterArn=cluster["clusterArn"],
            daemonTaskDefinitionArn=dtd1["daemonTaskDefinitionArn"],
            capacityProviderArns=[cp_desc["capacityProviderArn"]],
        )
        daemon_arn = created["daemonArn"]
        ctx.on_cleanup(lambda: ecs.delete_daemon(daemonArn=daemon_arn))

        first_deployments = _poll_until(
            lambda: ecs.list_daemon_deployments(daemonArn=daemon_arn).get("daemonDeployments", []),
            lambda deps: len(deps) >= 1 and all(d.get("targetDaemonRevisionArn") for d in deps),
            timeout_s=_budget_s(ctx, 90),
            ctx=ctx,
        )
        first_revision_arns = {d.get("targetDaemonRevisionArn") for d in first_deployments}
        first_deployment_arns = {d["daemonDeploymentArn"] for d in first_deployments}

        dtd2 = _register_daemon_td(ctx, ecs, family=dtd1["family"] + "-v2")
        updated = ecs.update_daemon(
            daemonArn=daemon_arn,
            daemonTaskDefinitionArn=dtd2["daemonTaskDefinitionArn"],
            capacityProviderArns=[cp_desc["capacityProviderArn"]],
        )
        update_deployment_arn = updated.get("deploymentArn")

        def _is_new(d):
            if update_deployment_arn:
                return d["daemonDeploymentArn"] == update_deployment_arn
            return d["daemonDeploymentArn"] not in first_deployment_arns

        second_deployments = _poll_until(
            lambda: ecs.list_daemon_deployments(daemonArn=daemon_arn).get("daemonDeployments", []),
            lambda deps: any(_is_new(d) for d in deps)
            and all(d.get("targetDaemonRevisionArn") for d in deps),
            timeout_s=_budget_s(ctx, 120),
            ctx=ctx,
        )
        new_deployments = [d for d in second_deployments if _is_new(d)]
        assert new_deployments, f"expected the UpdateDaemon deployment to be listed, got {second_deployments}"
        new_deployment = new_deployments[0]
        assert new_deployment["targetDaemonRevisionArn"] not in first_revision_arns, (
            f"expected a new deployment with a distinct target revision, got {second_deployments}"
        )

        all_arns = [d["daemonDeploymentArn"] for d in second_deployments]
        described = ecs.describe_daemon_deployments(daemonDeploymentArns=all_arns)
        assert not described.get("failures"), f"unexpected DescribeDaemonDeployments failures: {described}"
        described_by_arn = {d["daemonDeploymentArn"]: d for d in described["daemonDeployments"]}
        for listed_dep in second_deployments:
            desc_dep = described_by_arn.get(listed_dep["daemonDeploymentArn"])
            assert desc_dep is not None, f"expected {listed_dep['daemonDeploymentArn']} in describe response"
            assert desc_dep.get("targetDaemonRevision", {}).get("arn") == listed_dep.get(
                "targetDaemonRevisionArn"
            ), "List/Describe must agree on the target revision for the same deployment ARN"

        new_rev_arn = new_deployment["targetDaemonRevisionArn"]
        rev_desc = ecs.describe_daemon_revisions(daemonRevisionArns=[new_rev_arn])
        assert not rev_desc.get("failures"), f"unexpected DescribeDaemonRevisions failures: {rev_desc}"
        assert rev_desc["daemonRevisions"][0]["daemonTaskDefinitionArn"] == dtd2["daemonTaskDefinitionArn"], (
            f"expected the new deployment's target revision to reference {dtd2['daemonTaskDefinitionArn']}, "
            f"got {rev_desc['daemonRevisions'][0]}"
        )
    except (AssertionError, TimeoutError):
        raise
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"ECS Managed Daemon deployment ordering not exercisable in this account/region: {exc}"
        ) from None


def _delete_cp_and_wait(ecs, cp_name, cluster, timeout_s=600.0, interval_s=15.0):
    """Delete a cluster-scoped capacity provider (addressed through its cluster) and wait until it is
    gone, so the cluster can be deleted after it."""
    from botocore.exceptions import ClientError

    try:
        ecs.delete_capacity_provider(capacityProvider=cp_name, cluster=cluster)
    except ClientError as exc:
        if "does not exist" not in exc.response.get("Error", {}).get("Message", ""):
            raise
        return
    deadline = time.monotonic() + timeout_s
    while True:
        # A cluster-scoped provider is listed through its cluster; the API takes names or a cluster, not both.
        found = [cp for cp in ecs.describe_capacity_providers(cluster=cluster).get("capacityProviders", [])
                 if cp.get("name") == cp_name]
        if not found or found[0].get("status") == "INACTIVE":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"capacity provider {cp_name} still {found[0].get('status')!r} after {timeout_s:.0f}s")
        time.sleep(interval_s)


def _delete_cluster_when_free(ecs, cluster, timeout_s=600.0, interval_s=15.0):
    """Delete an ECS cluster, retrying while its capacity providers, tasks or attachments still hold it."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ClusterNotFoundException":
                return
            if code not in ("ClientException", "ClusterContainsTasksException", "UpdateInProgressException",
                            "ClusterContainsServicesException", "ClusterContainsContainerInstancesException") \
                    or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
