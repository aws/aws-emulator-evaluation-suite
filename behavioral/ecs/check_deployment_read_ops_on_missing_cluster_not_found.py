"""deployment-read-ops-on-missing-cluster-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "deployment-read-ops-on-missing-cluster-not-found"
GROUP = 'error-semantics'
SERVICES = ['ecs']
_CP_DOES_NOT_EXIST = "The specified capacity provider does not exist. Specify a valid name or ARN and try again."

_MI_INSTANCE_POLICY = "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"
_MI_INFRA_POLICY = "arn:aws:iam::aws:policy/AmazonECSInfrastructureRolePolicyForManagedInstances"

FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "essential": True,
        "command": ["sleep", "600"],
    }
]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises:
    accepting input that AWS refuses must not be reported as a mere error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _swap_cluster_in_arn(arn: str, old_cluster: str, new_cluster: str) -> str:
    return arn.replace(f"/{old_cluster}/", f"/{new_cluster}/", 1)


def _poll_until(fn, pred, *, timeout_s, interval_s=3):
    deadline = time.monotonic() + timeout_s
    while True:
        val = fn()
        if pred(val):
            return val
        if time.monotonic() >= deadline:
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


def _create_managed_instances_cp(ctx, ecs, cluster, subnets, sg):
    iam = ctx.client("iam")
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

    cp_name = ctx.unique_name("cp-")
    deadline = time.monotonic() + 90
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
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"could not provision a Managed Instances capacity provider: {exc}"
                ) from None
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_capacity_provider_and_wait(ecs, cp_name))
    return cp_name


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a nonexistent cluster, service deployment/revision reads return ClusterNotFoundException,
    ListDaemonDeployments returns empty, and DescribeDaemonDeployments/DescribeDaemonRevisions
    report the bogus ARN in `failures[]` rather than raising."""
    ecs = ctx.client("ecs")
    subnets, sg = _default_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": subnets[:1],
            "securityGroups": [sg],
            "assignPublicIp": "ENABLED",
        }
    }
    cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))["cluster"]
    cluster_name = cluster["clusterName"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td_arn))

    service_name = ctx.unique_name("svc-")
    ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=td_arn,
        desiredCount=0,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True))

    service_deployment_arn = _poll_until(
        lambda: ecs.list_service_deployments(cluster=cluster_name, service=service_name).get(
            "serviceDeployments", []
        ),
        lambda deployments: len(deployments) > 0,
        timeout_s=60,
    )[0]["serviceDeploymentArn"]
    service_revision_arn = ecs.describe_service_deployments(
        serviceDeploymentArns=[service_deployment_arn]
    )["serviceDeployments"][0]["targetServiceRevision"]["arn"]

    positive_revisions = ecs.describe_service_revisions(serviceRevisionArns=[service_revision_arn])[
        "serviceRevisions"
    ]
    assert positive_revisions and positive_revisions[0]["serviceRevisionArn"] == service_revision_arn, (
        f"DescribeServiceRevisions: positive control failed to resolve {service_revision_arn}, "
        f"got {positive_revisions}"
    )

    bogus_cluster = ctx.unique_name("no-such-cluster-")
    bogus_deployment_arn = _swap_cluster_in_arn(service_deployment_arn, cluster_name, bogus_cluster)
    bogus_revision_arn = _swap_cluster_in_arn(service_revision_arn, cluster_name, bogus_cluster)

    code, message = _error(
        lambda: ecs.describe_service_deployments(serviceDeploymentArns=[bogus_deployment_arn])
    )
    assert code == "ClusterNotFoundException", f"DescribeServiceDeployments: got {code}"
    assert message == "Cluster not found.", f"DescribeServiceDeployments: unexpected message {message!r}"

    code, message = _error(
        lambda: ecs.list_service_deployments(cluster=bogus_cluster, service=service_name)
    )
    assert code == "ClusterNotFoundException", f"ListServiceDeployments: got {code}"
    assert message == "Cluster not found.", f"ListServiceDeployments: unexpected message {message!r}"

    code, message = _error(
        lambda: ecs.describe_service_revisions(serviceRevisionArns=[bogus_revision_arn])
    )
    assert code == "ClusterNotFoundException", f"DescribeServiceRevisions: got {code}"
    assert message == "Cluster not found.", f"DescribeServiceRevisions: unexpected message {message!r}"

    try:
        cp_name = _create_managed_instances_cp(ctx, ecs, cluster_name, subnets, sg)
        cp_arn = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0][
            "capacityProviderArn"
        ]
        dtd_arn = ecs.register_daemon_task_definition(
            family=ctx.unique_name("daemontd-"),
            containerDefinitions=[
                {
                    "name": "app",
                    "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                    "cpu": 64,
                    "memory": 128,
                    "essential": True,
                }
            ],
        )["daemonTaskDefinitionArn"]
        ctx.on_cleanup(lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition=dtd_arn))
        daemon = ecs.create_daemon(
            clusterArn=cluster["clusterArn"],
            daemonName=ctx.unique_name("daemon-"),
            capacityProviderArns=[cp_arn],
            daemonTaskDefinitionArn=dtd_arn,
        )
        daemon_arn = daemon["daemonArn"]
        ctx.on_cleanup(lambda: ecs.delete_daemon(daemonArn=daemon_arn))
        daemon_deployment_arn = _poll_until(
            lambda: ecs.list_daemon_deployments(daemonArn=daemon_arn).get("daemonDeployments", []),
            lambda deployments: len(deployments) > 0,
            timeout_s=60,
        )[0]["daemonDeploymentArn"]
        daemon_revision_arn = ecs.describe_daemon_deployments(
            daemonDeploymentArns=[daemon_deployment_arn]
        )["daemonDeployments"][0]["targetDaemonRevision"]["arn"]

        bogus_daemon_arn = _swap_cluster_in_arn(daemon_arn, cluster_name, bogus_cluster)
        bogus_daemon_deployment_arn = _swap_cluster_in_arn(
            daemon_deployment_arn, cluster_name, bogus_cluster
        )
        bogus_daemon_revision_arn = _swap_cluster_in_arn(daemon_revision_arn, cluster_name, bogus_cluster)

        resp = ecs.list_daemon_deployments(daemonArn=bogus_daemon_arn)
        assert resp["daemonDeployments"] == [], f"ListDaemonDeployments: got {resp['daemonDeployments']}"

        resp = ecs.describe_daemon_deployments(daemonDeploymentArns=[bogus_daemon_deployment_arn])
        assert resp["daemonDeployments"] == [], f"DescribeDaemonDeployments: got {resp['daemonDeployments']}"
        assert resp.get("failures"), f"DescribeDaemonDeployments: expected failures[], got {resp}"

        resp = ecs.describe_daemon_revisions(daemonRevisionArns=[bogus_daemon_revision_arn])
        assert resp["daemonRevisions"] == [], f"DescribeDaemonRevisions: got {resp['daemonRevisions']}"
        assert resp.get("failures"), f"DescribeDaemonRevisions: expected failures[], got {resp}"
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"daemon deployment/revision ops not exercisable here: {exc}") from None


def _delete_capacity_provider_and_wait(ecs, cp_name, timeout_s=600.0, interval_s=10.0):
    """Delete the capacity provider, retrying while a daemon still holds it, then wait until it is
    gone so the cluster delete is not blocked. Raises once the deadline passes."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_capacity_provider(capacityProvider=cp_name)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and err.get("Message") == _CP_DOES_NOT_EXIST:
                return
            if err["Code"] != "UpdateInProgressException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)
    while True:
        cps = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"]
        if not cps or cps[0]["status"] == "INACTIVE":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"capacity provider {cp_name} still {cps[0]['status']} after {timeout_s}s")
        time.sleep(interval_s)



def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services, tasks or container instances remain, and a task's
    ENI stays in the shared network until the task has stopped, which keeps the network from
    being deleted.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s

    def arns(op, key, **kw):
        return [a for page in ecs.get_paginator(op).paginate(cluster=cluster, **kw) for a in page.get(key, [])]

    try:
        services = arns("list_services", "serviceArns")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ClusterNotFoundException":
            return
        raise
    for service in services:
        for call in (
            lambda s=service: ecs.update_service(cluster=cluster, service=s, desiredCount=0),
            lambda s=service: ecs.delete_service(cluster=cluster, service=s, force=True),
        ):
            try:
                call()
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "ClusterNotFoundException",
                    "ServiceNotFoundException",
                    "ServiceNotActiveException",
                ):
                    raise
    while True:
        for task in arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            try:
                ecs.stop_task(cluster=cluster, task=task, reason="sim2real teardown")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                    raise
        stopping = arns("list_tasks", "taskArns", desiredStatus="STOPPED")
        live = []
        for i in range(0, len(stopping), 100):
            live += [t for t in ecs.describe_tasks(cluster=cluster, tasks=stopping[i:i + 100])["tasks"]
                     if t.get("lastStatus") != "STOPPED"]
        if not live and not arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{len(live)} task(s) in {cluster} still not STOPPED after {timeout_s:.0f}s")
        time.sleep(interval_s)
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code == "ClusterContainsContainerInstancesException":
                for instance in arns("list_container_instances", "containerInstanceArns"):
                    try:
                        ecs.deregister_container_instance(cluster=cluster, containerInstance=instance, force=True)
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                            raise
            elif code not in (
                "ClusterContainsTasksException",
                "ClusterContainsServicesException",
                "UpdateInProgressException",
                "ResourceInUseException",
            ):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
