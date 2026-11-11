"""daemon-managed-rollout."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "daemon-managed-rollout"
GROUP = 'service-lifecycle'
SERVICES = ['ecs']

DEFAULT_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "cpu": 64,
        "memory": 128,
        "essential": True,
    }
]


def _fargate_network(ctx):
    """(subnets, security group) for awsvpc tasks from the run's shared network."""
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description="", ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _create_iam_role(ctx, iam, name_prefix, trust_service, *, managed_policy_arns=(), inline_policy=None):
    role_name = ctx.unique_name(name_prefix)[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = resp["Role"]["Arn"]
    for arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
        ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=a))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
    return role_name, role_arn


def _create_managed_instances_capacity_provider(ctx, ecs, cluster_name):
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    instance_role_name, instance_role_arn = _create_iam_role(
        ctx,
        iam,
        "ecsInstanceRole-",
        "ec2.amazonaws.com",
        managed_policy_arns=[
            "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"
        ],
    )
    iam.create_instance_profile(InstanceProfileName=instance_role_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=instance_role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=instance_role_name, RoleName=instance_role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=instance_role_name, RoleName=instance_role_name
        )
    )
    profile_arn = iam.get_instance_profile(InstanceProfileName=instance_role_name)["InstanceProfile"][
        "Arn"
    ]

    infra_inline_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": instance_role_arn}],
    }
    _infra_role_name, infra_role_arn = _create_iam_role(
        ctx,
        iam,
        "ecsInfra-",
        "ecs.amazonaws.com",
        managed_policy_arns=[
            "arn:aws:iam::aws:policy/AmazonECSInfrastructureRolePolicyForManagedInstances"
        ],
        inline_policy=infra_inline_policy,
    )

    subnets, sg = _fargate_network(ctx)

    def _create_once():
        cp_name = ctx.unique_name("sim2real-behav-ecs-cp-mi-")
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
                            "networkConfiguration": {"subnets": subnets[:1], "securityGroups": [sg]},
                            "monitoring": "basic",
                        },
                    },
                )
                break
            except Exception as exc:  # noqa: BLE001 — IAM propagation lag surfaces as a ClientError
                if time.monotonic() >= create_deadline:
                    raise AssertionError(
                        f"could not provision a Managed Instances capacity provider: {exc}"
                    ) from None
                time.sleep(2)
        ctx.on_cleanup(lambda: _delete_cp_and_wait(ecs, cp_name, cluster_name))
        settle_deadline = time.monotonic() + 180
        while True:
            cp = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0]
            if cp.get("status") == "ACTIVE":
                return cp_name, cp, True
            if cp.get("updateStatus") == "CREATE_FAILED" or cp.get("status") == "INACTIVE":
                return cp_name, cp, False
            if time.monotonic() >= settle_deadline:
                return cp_name, cp, False
            time.sleep(2)

    # A provider that settles to CREATE_FAILED (IAM propagation of the new infrastructure role)
    # never recovers in place, so creation is retried under a fresh name.
    attempts_deadline = time.monotonic() + 210
    cp_name, cp_desc, ok = _create_once()
    while not ok:
        if time.monotonic() >= attempts_deadline:
            raise AssertionError(
                "Managed Instances capacity provider repeatedly settled to CREATE_FAILED "
                f"(infrastructure-role access); not exercisable in this account: {cp_desc}"
            )
        time.sleep(2)
        cp_name, cp_desc, ok = _create_once()
    return cp_name, cp_desc


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _register_daemon_task_definition(ctx, ecs, family=None):
    family = family or ctx.unique_name("sim2real-behav-ecs-daemontd-")
    resp = ecs.register_daemon_task_definition(family=family, containerDefinitions=DEFAULT_CONTAINER_DEFS)
    arn = resp["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition=arn))
    return ecs.describe_daemon_task_definition(daemonTaskDefinition=arn)["daemonTaskDefinition"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDaemon alone drives a deployment to SUCCESSFUL; List/DescribeDaemonDeployments and
    DescribeDaemonRevisions agree on it, and a nonexistent revision ARN is reported MISSING."""
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-behav-ecs-daemoncl-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: _delete_cluster_when_free(ecs, cluster_name))
    try:
        cp_name, cp_desc = _create_managed_instances_capacity_provider(ctx, ecs, cluster_name)
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"could not provision a Managed Instances capacity provider: {exc}") from None

    try:
        assert cp_desc["status"] == "ACTIVE"

        dtd = _register_daemon_task_definition(ctx, ecs)
        daemon_name = ctx.unique_name("sim2real-behav-ecs-daemon-")
        try:
            created = ecs.create_daemon(
                daemonName=daemon_name,
                clusterArn=cluster_name,
                daemonTaskDefinitionArn=dtd["daemonTaskDefinitionArn"],
                capacityProviderArns=[cp_desc["capacityProviderArn"]],
            )
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(f"CreateDaemon not usable in this account/region: {exc}") from None

        daemon_arn = created["daemonArn"]
        ctx.on_cleanup(lambda: ecs.delete_daemon(daemonArn=daemon_arn))
        initial_deployment_arn = created.get("deploymentArn")
        assert initial_deployment_arn, "CreateDaemon response missing the initial deploymentArn"

        deployments = _poll_until(
            lambda: ecs.list_daemon_deployments(daemonArn=daemon_arn).get("daemonDeployments", []),
            lambda deps: any(
                d["daemonDeploymentArn"] == initial_deployment_arn and d.get("targetDaemonRevisionArn")
                for d in deps
            ),
            timeout_s=_budget_s(ctx, 90.0),
            interval_s=2,
            description="CreateDaemon produces a DaemonDeployment without any further client action",
            ctx=ctx,
        )
        assert deployments, "expected at least one daemon deployment after CreateDaemon"
        deployment_arns = [d["daemonDeploymentArn"] for d in deployments]
        assert initial_deployment_arn in deployment_arns, (
            f"CreateDaemon's own deploymentArn {initial_deployment_arn!r} must be the one "
            f"ListDaemonDeployments independently reports, got {deployment_arns}"
        )

        described = ecs.describe_daemon_deployments(daemonDeploymentArns=deployment_arns)
        assert not described.get("failures"), f"unexpected DescribeDaemonDeployments failures: {described}"
        described_by_arn = {d["daemonDeploymentArn"]: d for d in described["daemonDeployments"]}
        for listed_dep in deployments:
            desc_dep = described_by_arn.get(listed_dep["daemonDeploymentArn"])
            assert desc_dep is not None, f"expected {listed_dep['daemonDeploymentArn']} in describe response"
            assert desc_dep.get("targetDaemonRevision", {}).get("arn") == listed_dep.get(
                "targetDaemonRevisionArn"
            ), "List/Describe must agree on the target revision for the same deployment ARN"

        terminal = {"SUCCESSFUL", "STOPPED", "ROLLBACK_SUCCESSFUL", "ROLLBACK_FAILED"}
        settled = _poll_until(
            lambda: ecs.describe_daemon_deployments(
                daemonDeploymentArns=[initial_deployment_arn]
            )["daemonDeployments"][0],
            lambda d: d.get("status") in terminal,
            timeout_s=_budget_s(ctx, 120.0),
            interval_s=2,
            description="the CreateDaemon deployment reaches a terminal status",
            ctx=ctx,
        )
        assert settled["status"] == "SUCCESSFUL", (
            f"expected the CreateDaemon deployment to finish SUCCESSFUL, got "
            f"status={settled['status']!r} ({settled!r})"
        )

        target_rev_arn = settled.get("targetDaemonRevision", {}).get("arn")
        assert target_rev_arn, f"the settled CreateDaemon deployment names no target revision: {settled!r}"
        rev_desc = ecs.describe_daemon_revisions(daemonRevisionArns=[target_rev_arn])
        assert not rev_desc.get("failures"), f"unexpected DescribeDaemonRevisions failures: {rev_desc}"
        assert rev_desc["daemonRevisions"][0]["daemonTaskDefinitionArn"] == dtd["daemonTaskDefinitionArn"], (
            f"expected the deployment's target revision to reference {dtd['daemonTaskDefinitionArn']}, "
            f"got {rev_desc['daemonRevisions'][0]}"
        )

        # The nil UUID keeps the ARN well-formed; a malformed id is rejected with
        # InvalidParameterException instead of being reported as MISSING.
        bogus_rev_arn = target_rev_arn.rsplit("/", 1)[0] + "/00000000-0000-0000-0000-000000000000"
        bogus_resp = ecs.describe_daemon_revisions(daemonRevisionArns=[bogus_rev_arn])
        real_rev_arns = {r.get("daemonRevisionArn") for r in bogus_resp.get("daemonRevisions", [])}
        assert bogus_rev_arn not in real_rev_arns, (
            f"a nonexistent daemon revision ARN must not be fabricated into daemonRevisions, got {bogus_resp}"
        )
        failures_by_arn = {f.get("arn"): f for f in bogus_resp.get("failures", [])}
        assert bogus_rev_arn in failures_by_arn, (
            f"expected {bogus_rev_arn} reported in DescribeDaemonRevisions failures, got {bogus_resp}"
        )
        assert failures_by_arn[bogus_rev_arn].get("reason") == "MISSING", (
            "expected reason MISSING for a nonexistent daemon revision ARN, matching every other "
            f"ECS Describe* not-found convention; got {failures_by_arn[bogus_rev_arn]}"
        )
    except (AssertionError, TimeoutError):
        raise
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"ECS Managed Daemon rollout not exercisable in this account/region: {exc}"
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
