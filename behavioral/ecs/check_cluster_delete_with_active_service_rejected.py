"""cluster-delete-with-active-service-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cluster-delete-with-active-service-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster is rejected with ClusterContainsServicesException while an ACTIVE service
    exists, the cluster is left untouched by the rejected call, and once the blocking service is
    gone the identical DeleteCluster call succeeds."""
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx)
    net = _default_network(ctx)
    task_def = _register_fargate_task_def(ctx, ctx.unique_name("sim2real-ecs-td-"))

    service_name = ctx.unique_name("sim2real-ecs-svc-")
    ecs.create_service(
        cluster=cluster["clusterArn"],
        serviceName=service_name,
        taskDefinition=task_def["taskDefinitionArn"],
        desiredCount=0,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": net["subnets"],
                "securityGroups": net["security_groups"],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=[{"key": "sim2real", "value": "true"}],
    )

    def _cleanup_service():
        try:
            ecs.delete_service(cluster=cluster["clusterArn"], service=service_name, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ClusterNotFoundException",
                "ServiceNotFoundException",
            ):
                raise

    ctx.on_cleanup(_cleanup_service)

    code, message = _error(lambda: ecs.delete_cluster(cluster=cluster["clusterArn"]))
    assert code == "ClusterContainsServicesException", f"expected ClusterContainsServicesException, got {code}"
    assert message == "The Cluster cannot be deleted while Services are active.", (
        f"unexpected message: {message!r}"
    )

    described = ecs.describe_clusters(clusters=[cluster["clusterArn"]])["clusters"][0]
    assert described["status"] == "ACTIVE", f"cluster should be untouched by the rejected delete: {described}"

    # restore: remove the one blocking condition, then the identical call must succeed.
    ecs.delete_service(cluster=cluster["clusterArn"], service=service_name, force=True)
    _poll_service_inactive(ecs, cluster["clusterArn"], service_name)

    ecs.delete_cluster(cluster=cluster["clusterArn"])
    remaining = ecs.describe_clusters(clusters=[cluster["clusterArn"]])["clusters"]
    assert not any(c["status"] == "ACTIVE" for c in remaining), (
        f"cluster still ACTIVE after the blocking service was removed and DeleteCluster retried: {remaining}"
    )


from botocore.exceptions import ClientError


def _error(fn):
    """Call fn(); return its (code, message). A success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_service_inactive(ecs, cluster_arn, service_name, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        described = ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"]
        if not described or described[0]["status"] == "INACTIVE":
            return
        last = described[0]["status"]
        time.sleep(interval_s)
    raise AssertionError(f"service did not reach INACTIVE within {timeout_s}s; last status={last}")


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError("no subnets available in VPC to place Fargate tasks")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    ).get("SecurityGroups", [])
    return {
        "subnets": [s["SubnetId"] for s in subnets[:2]],
        "security_groups": [sgs[0]["GroupId"]] if sgs else [],
    }


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-cluster-")
    cluster = ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": "true"}])["cluster"]

    def _cleanup(arn=cluster["clusterArn"]):
        try:
            ecs.delete_cluster(cluster=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return cluster


def _register_fargate_task_def(ctx, family, command=None):
    ecs = ctx.client("ecs")
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": command or ["sleep", "600"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    td = resp["taskDefinition"]

    def _cleanup(arn=td["taskDefinitionArn"]):
        try:
            ecs.deregister_task_definition(taskDefinition=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted"))
            ):
                raise
        ecs.delete_task_definitions(taskDefinitions=[arn])

    ctx.on_cleanup(_cleanup)
    return td


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
