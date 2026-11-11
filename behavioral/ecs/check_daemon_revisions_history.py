"""daemon-revisions-history."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "daemon-revisions-history"
GROUP = "ordering"
SERVICES = ["ecs"]

_ECS_TAGS = [{"key": "sim2real:managed", "value": "true"}]
_IAM_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDaemonRevisions returns revision history in creation order after multiple UpdateDaemon calls."""
    env = _setup_managed_instances_env(ctx)
    ecs = ctx.client("ecs")

    td_arns = [_register_daemon_task_def(ctx) for _ in range(3)]
    daemon_name = ctx.unique_name("sim2real-daemon-")
    create_resp = ecs.create_daemon(
        daemonName=daemon_name,
        clusterArn=env["cluster_arn"],
        daemonTaskDefinitionArn=td_arns[0],
        capacityProviderArns=[env["capacity_provider_arn"]],
        tags=_ECS_TAGS,
    )
    daemon_arn = create_resp["daemonArn"]
    ctx.on_cleanup(lambda: _delete_daemon_best_effort(ecs, daemon_arn))

    deployment_arns = [create_resp["deploymentArn"]]
    for td_arn in td_arns[1:]:
        upd = ecs.update_daemon(daemonArn=daemon_arn, daemonTaskDefinitionArn=td_arn, capacityProviderArns=[env["capacity_provider_arn"]])
        deployment_arns.append(upd["deploymentArn"])
        # Not a poll: spaces consecutive UpdateDaemon calls apart so their revisions do not
        # tie on createdAt if the service's timestamp precision is coarser than the call rate.
        time.sleep(1.0)

    summaries = _poll_until(
        lambda: ecs.list_daemon_deployments(daemonArn=daemon_arn)["daemonDeployments"],
        lambda entries: len(entries) >= len(deployment_arns),
        timeout_s=60.0,
        interval_s=3.0,
    )
    summary_by_deployment = {s["daemonDeploymentArn"]: s for s in summaries if s["daemonDeploymentArn"] in deployment_arns}
    revision_arns_in_order = [summary_by_deployment[arn]["targetDaemonRevisionArn"] for arn in deployment_arns]
    assert len(set(revision_arns_in_order)) == len(revision_arns_in_order), "each UpdateDaemon call must mint a distinct revision"

    revisions = ecs.describe_daemon_revisions(daemonRevisionArns=revision_arns_in_order)["daemonRevisions"]
    revisions_by_arn = {r["daemonRevisionArn"]: r for r in revisions}
    assert set(revisions_by_arn) == set(revision_arns_in_order), (
        f"DescribeDaemonRevisions did not resolve every requested revision: "
        f"requested {revision_arns_in_order}, got {sorted(revisions_by_arn)}"
    )

    created_ordered = [revisions_by_arn[arn]["createdAt"] for arn in revision_arns_in_order]
    assert created_ordered == sorted(created_ordered), (
        f"DescribeDaemonRevisions createdAt values are not in creation order: {created_ordered}"
    )

    task_def_ordered = [revisions_by_arn[arn]["daemonTaskDefinitionArn"] for arn in revision_arns_in_order]
    assert task_def_ordered == td_arns, (
        f"revision history task definitions don't match the update order: expected {td_arns}, got {task_def_ordered}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


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
        tags=_ECS_TAGS,
    )
    arn = resp["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: _delete_daemon_task_def_best_effort(ecs, arn))
    return arn


def _delete_daemon_task_def_best_effort(ecs, arn):
    from botocore.exceptions import ClientError

    try:
        ecs.delete_daemon_task_definition(daemonTaskDefinition=arn)
    except ClientError as err:
        message = err.response.get("Error", {}).get("Message", "").lower()
        if "does not exist" not in message and "not found" not in message:
            raise


def _setup_managed_instances_env(ctx):
    
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

    try:
        infra_role_arn = iam.create_role(
            RoleName=infra_role_name, AssumeRolePolicyDocument=infra_trust, Tags=_IAM_TAGS
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=infra_role_name))
        iam.attach_role_policy(RoleName=infra_role_name, PolicyArn=infra_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=infra_role_name, PolicyArn=infra_policy_arn))

        iam.create_role(
            RoleName=instance_role_name, AssumeRolePolicyDocument=instance_trust, Tags=_IAM_TAGS
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=instance_role_name))
        iam.attach_role_policy(RoleName=instance_role_name, PolicyArn=instance_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=instance_role_name, PolicyArn=instance_policy_arn))

        iam.create_instance_profile(InstanceProfileName=profile_name, Tags=_IAM_TAGS)
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

    security_groups = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not security_groups:
        raise AssertionError("unreachable: no default security group available for ECS Managed Instances network configuration")
    security_group_ids = [security_groups[0]["GroupId"]]

    cluster_name = ctx.unique_name("sim2real-daemon-cluster-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name, tags=_ECS_TAGS)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_free(ecs, cluster_arn))

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
                        "networkConfiguration": {"subnets": subnet_ids, "securityGroups": security_group_ids},
                        "instanceRequirements": {
                            "vCpuCount": {"min": 1, "max": 2},
                            "memoryMiB": {"min": 512, "max": 2048},
                        },
                    },
                },
                tags=_ECS_TAGS,
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
    ctx.on_cleanup(lambda: _delete_cp_and_wait(ecs, cp_name, cluster_name))

    def _cp_status():
        d = ecs.describe_capacity_providers(capacityProviders=[cp_arn])["capacityProviders"]
        return d[0]["status"] if d else None

    try:
        status = _poll_until(_cp_status, lambda s: s == "ACTIVE", timeout_s=180.0, interval_s=5.0)
    except AssertionError as err:
        raise AssertionError(
            f"unreachable: Managed Instances capacity provider never reached ACTIVE ({err})"
        )
    assert status == "ACTIVE", f"expected the capacity provider to converge on ACTIVE, got {status!r}"

    return {"cluster_arn": cluster_arn, "cluster_name": cluster_name, "capacity_provider_arn": cp_arn}


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
