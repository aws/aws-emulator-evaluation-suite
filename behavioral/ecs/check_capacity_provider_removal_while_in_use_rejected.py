"""capacity-provider-removal-while-in-use-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-provider-removal-while-in-use-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutClusterCapacityProviders is refused with ResourceInUseException when it would drop a
    capacity provider that a running service still depends on, and the cluster's capacity
    provider association is left unchanged; removal succeeds once the service is gone."""

    ecs = ctx.client("ecs")
    iam = ctx.client("iam")
    subnets, sg_id = _default_network(ctx)

    cluster_arn = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-ecs-"))["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _retry_busy(lambda: ecs.delete_cluster(cluster=cluster_arn)))
    _put_cluster_capacity_providers_with_slr_retry(
        ecs,
        iam,
        cluster=cluster_arn,
        capacityProviders=["FARGATE"],
        defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
    )

    family = ctx.unique_name("sim2real-cpiu-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36", "essential": True, "command": ["sleep", "3600"]}
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    service_name = ctx.unique_name("sim2real-cpiu-svc-")
    net_cfg = {"awsvpcConfiguration": {"subnets": subnets, "securityGroups": [sg_id], "assignPublicIp": "ENABLED"}}
    try:
        ecs.create_service(
            cluster=cluster_arn,
            serviceName=service_name,
            taskDefinition=td_arn,
            desiredCount=1,
            capacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
            networkConfiguration=net_cfg,
        )
    except ClientError as e:
        raise AssertionError(f"unreachable: CreateService with FARGATE strategy not usable in this environment: {e}")
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_arn, service=service_name, force=True))

    _poll_until(
        lambda: ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]["runningCount"],
        lambda n: n >= 1,
        timeout_s=180,
        interval_s=6,
    )

    # break exactly one precondition: try to drop FARGATE from the cluster while the running
    # service still depends on it
    code, message = _error(
        lambda: ecs.put_cluster_capacity_providers(cluster=cluster_arn, capacityProviders=[], defaultCapacityProviderStrategy=[])
    )
    assert code == "ResourceInUseException", (
        f"expected ResourceInUseException removing FARGATE while a running service still "
        f"depends on it, got {code!r}"
    )
    assert message == "The specified capacity provider is in use and cannot be removed.", (
        f"unexpected message: {message!r}"
    )

    # the forbidden effect did not happen: the cluster still lists FARGATE as a capacity provider
    still = ecs.describe_clusters(clusters=[cluster_arn])["clusters"][0]
    assert "FARGATE" in still["capacityProviders"], (
        f"a rejected removal must leave FARGATE attached, got capacityProviders={still['capacityProviders']!r}"
    )

    # positive control: once the dependent service is gone, the same removal succeeds
    ecs.delete_service(cluster=cluster_arn, service=service_name, force=True)
    _poll_until(
        lambda: ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]["status"],
        lambda s: s == "INACTIVE",
        timeout_s=180,
        interval_s=6,
    )
    _put_cluster_capacity_providers_with_slr_retry(
        ecs, iam, cluster=cluster_arn, capacityProviders=[], defaultCapacityProviderStrategy=[]
    )
    # the accepted removal settles asynchronously (the cluster's attachment update runs after
    # the call returns), so read until the association is empty
    try:
        _poll_until(
            lambda: ecs.describe_clusters(clusters=[cluster_arn])["clusters"][0]["capacityProviders"],
            lambda cps: cps == [],
            timeout_s=180,
            interval_s=5,
        )
    except AssertionError as exc:
        raise AssertionError(
            f"expected the identical removal to succeed once the dependent service is gone: {exc}"
        ) from None


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, so an
    over-permissive target accepting a call real AWS refuses fails as a success, not as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _put_cluster_capacity_providers_with_slr_retry(ecs, iam, timeout_s=120, interval_s=10, **kwargs):
    """PutClusterCapacityProviders depends on the AWSServiceRoleForECS service-linked role.
    In accounts where that role hasn't been created yet (e.g. never used ECS capacity
    providers before), the first call(s) fail with InvalidParameterException while the role
    is provisioned/propagates; ensure it exists and retry until it's usable."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return ecs.put_cluster_capacity_providers(**kwargs)
        except ClientError as e:
            err = e.response["Error"]
            msg = err.get("Message", "")
            if err.get("Code") == "InvalidParameterException" and "service linked role" in msg.lower():
                last_exc = e
                try:
                    iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
                except ClientError:
                    pass
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _poll_until(probe, predicate, timeout_s=120, interval_s=3):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _default_network(ctx):

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("unreachable: no shared network VPC available")
    vpc_id = vpcs[0]["VpcId"]
    subnets = [s["SubnetId"] for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]][:2]
    if not subnets:
        raise AssertionError("unreachable: shared network has no subnets")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("unreachable: shared network has no default security group")
    return subnets, sgs[0]["GroupId"]


def _retry_busy(fn, timeout_s=120, interval_s=5):
    """Teardown: retry fn while the cluster answers UpdateInProgressException (a
    capacity-provider change still settling); any other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "UpdateInProgressException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
