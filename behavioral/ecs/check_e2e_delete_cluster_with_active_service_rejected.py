"""e2e-delete-cluster-with-active-service-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-delete-cluster-with-active-service-rejected"
GROUP = "e2e"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """DeleteCluster on a cluster that still has an ACTIVE service is rejected with
    ClusterContainsServicesException, the cluster is NOT deleted, and once the blocking
    service is removed the identical DeleteCluster call succeeds (positive control).
    """
    ecs = ctx.client("ecs")
    net = _default_network_config(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-negdel-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])[
        "cluster"
    ]["clusterArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: ecs.delete_cluster(cluster=cluster_arn)))

    family = ctx.unique_name("sim2real-ecs-negdel-td-")
    task_def_arn = _register_sleep_task_def(ctx, family)
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    service_name = ctx.unique_name("sim2real-ecs-negdel-svc-")
    _call_with_slr_retry(
        lambda: ecs.create_service(
            cluster=cluster_arn,
            serviceName=service_name,
            taskDefinition=task_def_arn,
            desiredCount=1,
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": net["subnets"],
                    "securityGroups": net["securityGroups"],
                    "assignPublicIp": "ENABLED",
                }
            },
            tags=[{"key": "sim2real", "value": "true"}],
        )
    )
    ctx.on_cleanup(
        lambda: _ignore(lambda: ecs.delete_service(cluster=cluster_arn, service=service_name, force=True))
    )

    def _describe_service() -> dict:
        return ecs.describe_services(cluster=cluster_arn, services=[service_name])["services"][0]

    _poll_until(
        _describe_service,
        lambda s: s["runningCount"] == 1 and s["pendingCount"] == 0,
        timeout_s=300.0,
        interval_s=10.0,
    )

    # --- break exactly one thing: try to delete the cluster while the service is ACTIVE ---
    code, message = _error(lambda: ecs.delete_cluster(cluster=cluster_arn))
    assert code == "ClusterContainsServicesException", (
        f"expected ClusterContainsServicesException deleting a cluster with an ACTIVE service, got {code}"
    )
    assert message == "The Cluster cannot be deleted while Services are active.", f"unexpected message: {message!r}"

    # Effect absent: the cluster must still be ACTIVE, not deleted.
    cluster_state = ecs.describe_clusters(clusters=[cluster_arn])["clusters"][0]
    assert cluster_state["status"] == "ACTIVE", (
        f"cluster must be untouched by the rejected delete, got status={cluster_state['status']!r}"
    )

    # --- positive control: remove the one blocking condition, then the same call succeeds ---
    ecs.delete_service(cluster=cluster_arn, service=service_name, force=True)
    _poll_until(
        _describe_service,
        lambda s: s["status"] == "INACTIVE",
        timeout_s=180.0,
        interval_s=5.0,
    )

    ecs.delete_cluster(cluster=cluster_arn)

    def _describe_cluster() -> dict:
        clusters = ecs.describe_clusters(clusters=[cluster_arn])["clusters"]
        return clusters[0] if clusters else {"status": "GONE"}

    final = _poll_until(
        _describe_cluster,
        lambda c: c["status"] in ("INACTIVE", "GONE"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert final["status"] in ("INACTIVE", "GONE"), (
        f"cluster should be deleted once the blocking service is gone, got status={final['status']!r}"
    )


def _ignore(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _default_network_config(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to launch Fargate tasks")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to launch Fargate tasks into")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return {
        "subnets": [s["SubnetId"] for s in subnets[:2]],
        "securityGroups": [sgs[0]["GroupId"]] if sgs else [],
    }


def _call_with_slr_retry(fn, *, timeout_s=90.0, interval_s=5.0):
    """Retry an ECS call that can transiently fail with InvalidParameterException
    ('Unable to assume the service linked role...') while AWSServiceRoleForECS propagates."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            msg = e.response.get("Error", {}).get("Message", "")
            if "service linked role" not in msg.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _register_sleep_task_def(ctx, family, command=None):
    ecs = ctx.client("ecs")
    container = {
        "name": "app",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "command": command or ["sleep", "1800"],
        "essential": True,
    }
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[container],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    return resp["taskDefinition"]["taskDefinitionArn"]


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
