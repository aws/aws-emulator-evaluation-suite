"""e2e-daemon-instance-join-schedules-task-consequence."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-daemon-instance-join-schedules-task-consequence"
GROUP = "state-machine"
SERVICES = ["ecs"]

_ECS_TAGS = [{"key": "sim2real:managed", "value": "true"}, {"key": "sim2real:prefix", "value": "sim2real-behav"}]
_IAM_TAGS = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "plane:control")
def run(ctx) -> None:
    """A daemon on an ACTIVE Managed Instances capacity provider launches no instance and schedules
    no task: once its rollout completes, DescribeDaemon reports zero running and zero withoutDaemon
    counts and the cluster holds no container instance and no task.
    """
    from botocore.exceptions import ClientError

    ecs = ctx.client("ecs")
    net = _default_network(ctx)

    infra_role_arn = _create_infra_role(ctx)
    instance_profile_arn = _create_instance_profile(ctx)

    cluster = ctx.unique_name("sim2real-ecs-daemon-cluster-")
    ecs.create_cluster(clusterName=cluster, tags=_ECS_TAGS)
    ctx.on_cleanup(lambda: _delete_cluster_when_free(ecs, cluster))

    cp_name = ctx.unique_name("sim2real-ecs-daemon-cp-")

    def _create_cp():
        return ecs.create_capacity_provider(
            name=cp_name,
            cluster=cluster,
            managedInstancesProvider={
                "infrastructureRoleArn": infra_role_arn,
                "instanceLaunchTemplate": {
                    "ec2InstanceProfileArn": instance_profile_arn,
                    "instanceRequirements": {
                        "vCpuCount": {"min": 2, "max": 4},
                        "memoryMiB": {"min": 4096, "max": 8192},
                    },
                    "networkConfiguration": {
                        "subnets": net["subnet_ids"][:1],
                        "securityGroups": [net["sg_id"]],
                    },
                    "monitoring": "basic",
                },
            },
            tags=_ECS_TAGS,
        )

    try:
        # The infra role and instance profile just created are not immediately assumable by
        # ecs.amazonaws.com / ec2.amazonaws.com; retry past that propagation lag instead of
        # guessing its duration with a blind sleep.
        cp_resp = _call_with_role_propagation_retry(_create_cp)
    except ClientError as e:
        if e.response["Error"]["Code"] == "UnsupportedFeatureException":
            raise AssertionError(
                "ECS Managed Instances capacity providers (required for daemons) are not "
                "supported in this account/region"
            )
        raise
    cp_arn = cp_resp["capacityProvider"]["capacityProviderArn"]
    ctx.on_cleanup(lambda: _detach_and_delete_capacity_provider(ecs, cluster, cp_name))

    _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=5,
    )

    ecs.put_cluster_capacity_providers(
        cluster=cluster,
        capacityProviders=[cp_name],
        defaultCapacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1}],
    )
    _poll_until(
        lambda: ecs.describe_clusters(clusters=[cluster])["clusters"][0]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=5,
    )

    daemon_family = ctx.unique_name("sim2real-ecs-daemon-td-")
    daemon_td_arn = ecs.register_daemon_task_definition(
        family=daemon_family,
        containerDefinitions=[
            {
                "name": "monitor",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "command": ["sleep", "infinity"],
                "essential": True,
                "cpu": 128,
                "memory": 128,
            }
        ],
        tags=_ECS_TAGS,
    )["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition=daemon_td_arn))

    daemon_name = ctx.unique_name("sim2real-ecs-daemon-")
    daemon_arn = ecs.create_daemon(
        clusterArn=cluster,
        daemonName=daemon_name,
        daemonTaskDefinitionArn=daemon_td_arn,
        capacityProviderArns=[cp_arn],
        tags=_ECS_TAGS,
    )["daemonArn"]
    ctx.on_cleanup(lambda: ecs.delete_daemon(daemonArn=daemon_arn))

    # Positive control: the daemon itself is healthy and really is bound to this provider. Without
    # this, a daemon that failed to create would produce the same empty instance list below.
    _poll_until(
        lambda: ecs.describe_daemon(daemonArn=daemon_arn)["daemon"]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=5,
    )
    _assert_rollout_complete_over_zero_instances(ecs, daemon_arn, cp_arn, when="as soon as ACTIVE")

    # Absence by contrast: the completed rollout is ordered after the daemon's placement decision,
    # so the cluster read now is its settled answer: nothing launched, nothing scheduled.
    instances = ecs.list_container_instances(cluster=cluster)["containerInstanceArns"]
    assert instances == [], (
        f"a container instance registered with {cluster} from a daemon alone, with no other "
        f"workload on the capacity provider: {instances!r}"
    )
    tasks = ecs.list_tasks(cluster=cluster)["taskArns"]
    assert tasks == [], f"a task was scheduled with no container instance to host it: {tasks!r}"

    # A second DescribeDaemon read after the cluster read reports the same completed rollout.
    _assert_rollout_complete_over_zero_instances(
        ecs, daemon_arn, cp_arn, when="after the cluster was read"
    )


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    public = [s["SubnetId"] for s in subnets if s.get("MapPublicIpOnLaunch")]
    subnet_ids = public or [s["SubnetId"] for s in subnets]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sgs[0]["GroupId"]}


def _assert_rollout_complete_over_zero_instances(ecs, daemon_arn, cp_arn, *, when, timeout_s=300.0):
    """Assert one revision on `cp_arn` with zero running and zero withoutDaemon counts.

    currentRevisions stays empty for minutes after the daemon turns ACTIVE, so it is polled.
    """
    revisions = _poll_until(
        lambda: ecs.describe_daemon(daemonArn=daemon_arn)["daemon"]["currentRevisions"],
        lambda revs: len(revs) >= 1,
        timeout_s=timeout_s,
        interval_s=10,
    )
    assert len(revisions) == 1, f"expected one current revision {when}, got {revisions!r}"
    providers = revisions[0]["capacityProviders"]
    assert [p["arn"] for p in providers] == [cp_arn], (
        f"the daemon revision names providers {[p.get('arn') for p in providers]!r} {when}, "
        f"expected exactly [{cp_arn!r}]"
    )
    assert providers[0]["runningCount"] == 0, (
        f"the daemon reports runningCount={providers[0]['runningCount']} {when} with no container "
        f"instance in the cluster"
    )
    assert providers[0]["withoutDaemonCount"] == 0, (
        f"the daemon reports withoutDaemonCount={providers[0]['withoutDaemonCount']} {when}; ECS "
        f"must report no instance is missing the daemon, because there is no instance at all"
    )
    assert revisions[0]["totalRunningCount"] == 0, revisions[0]
    assert revisions[0]["totalWithoutDaemonCount"] == 0, revisions[0]


def _detach_and_delete_capacity_provider(ecs, cluster_name, cp_name, timeout_s=120.0):
    """Detach the provider from the cluster's DEFAULT strategy before deleting it.

    Otherwise the delete lands in DELETE_FAILED and DeleteCluster refuses permanently.
    """
    from botocore.exceptions import ClientError

    try:
        ecs.put_cluster_capacity_providers(
            cluster=cluster_name, capacityProviders=[], defaultCapacityProviderStrategy=[]
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise
    try:
        ecs.delete_capacity_provider(capacityProvider=cp_name)
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] != "ClusterNotFoundException"
            and not (err["Code"] == "ClientException" and "The specified capacity provider does not exist" in err.get("Message", ""))
        ):
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ecs.describe_capacity_providers(capacityProviders=[cp_name])
        found = resp.get("capacityProviders") or []
        if not found or found[0].get("status") == "INACTIVE":
            return
        time.sleep(5)


def _call_with_role_propagation_retry(fn, *, timeout_s=120.0, interval_s=5.0):
    """Retry fn() while a freshly created IAM role or instance profile is not yet assumable."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ClientException", "InvalidParameterException"):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    assert last_err is not None
    raise last_err


def _create_infra_role(ctx) -> str:
    """ECS infrastructure role: assumed by the ecs.amazonaws.com service to manage the
    Managed Instances EC2 lifecycle on the caller's behalf."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecs-mi-infra-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_IAM_TAGS)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonECSInfrastructureRolePolicyForManagedInstances"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_instance_profile(ctx) -> str:
    """ECS Managed Instances instance profile. The AWS-managed infrastructure policy scopes
    iam:PassRole to role names starting with 'ecsInstanceRole', so this role deliberately
    does not use the sim2real- naming convention."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("ecsInstanceRole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_IAM_TAGS)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    profile_name = role_name
    iam.create_instance_profile(InstanceProfileName=profile_name, Tags=_IAM_TAGS)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name))

    return iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]["Arn"]


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
