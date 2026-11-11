"""e2e-blue-green-deployment-full-cycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-blue-green-deployment-full-cycle"
GROUP = "e2e"
SERVICES = ["ecs"]

_TAGS = [{"key": "sim2real:check", "value": CHECK}]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An EXTERNAL-controller service runs a blue/green cycle through two task
    sets: promoting the green task set to PRIMARY actually demotes blue, and
    tearing down the losing task set leaves only the winner behind."""
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _fargate_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }

    cluster_name = ctx.unique_name("sim2real-ecs-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_cluster_once_drained(ecs, cluster_name))

    family = ctx.unique_name("sim2real-ecs-taskdef-")
    td_blue_arn = _register_td(ecs, family, "blue")
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_blue_arn))
    td_green_arn = _register_td(ecs, family, "green")
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_green_arn))

    service_name = ctx.unique_name("sim2real-ecs-svc-")
    _ensure_service_linked_role(ctx)
    _create_service_with_retry(
        ecs,
        cluster=cluster_name,
        serviceName=service_name,
        desiredCount=1,
        deploymentController={"type": "EXTERNAL"},
        tags=_TAGS,
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True))
    )

    blue_ts = ecs.create_task_set(
        cluster=cluster_name,
        service=service_name,
        taskDefinition=td_blue_arn,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
        scale={"value": 100.0, "unit": "PERCENT"},
        tags=_TAGS,
    )["taskSet"]
    blue_ts_id = blue_ts["id"]
    _wait_steady_state(ctx, cluster_name, service_name, blue_ts_id, timeout_s=240)

    # First task set in an EXTERNAL service becomes PRIMARY automatically; make
    # that explicit so the check's setup doesn't depend on an unasserted detail.
    ecs.update_service_primary_task_set(
        cluster=cluster_name, service=service_name, primaryTaskSet=blue_ts["taskSetArn"]
    )
    blue_status = _describe_task_set(ecs, cluster_name, service_name, blue_ts_id)["status"]
    assert blue_status == "PRIMARY", f"expected the sole task set to be PRIMARY, got {blue_status!r}"

    green_ts = ecs.create_task_set(
        cluster=cluster_name,
        service=service_name,
        taskDefinition=td_green_arn,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
        scale={"value": 100.0, "unit": "PERCENT"},
        tags=_TAGS,
    )["taskSet"]
    green_ts_id = green_ts["id"]
    _wait_steady_state(ctx, cluster_name, service_name, green_ts_id, timeout_s=240)
    green_status_before = _describe_task_set(ecs, cluster_name, service_name, green_ts_id)["status"]
    assert green_status_before == "ACTIVE", (
        f"a freshly-stabilized second task set should be ACTIVE (not yet promoted), "
        f"got {green_status_before!r}"
    )

    # Promote green to primary -- the deployment's "continuation to completion".
    ecs.update_service_primary_task_set(
        cluster=cluster_name, service=service_name, primaryTaskSet=green_ts["taskSetArn"]
    )
    green_after = _describe_task_set(ecs, cluster_name, service_name, green_ts_id)
    blue_after = _describe_task_set(ecs, cluster_name, service_name, blue_ts_id)
    assert green_after["status"] == "PRIMARY", f"expected green promoted to PRIMARY, got {green_after['status']!r}"
    assert blue_after["status"] == "ACTIVE", (
        f"promoting green must demote the formerly-primary blue to ACTIVE, got {blue_after['status']!r}"
    )

    # Tear down the losing (blue) task set; the winner must remain intact.
    ecs.delete_task_set(cluster=cluster_name, service=service_name, taskSet=blue_ts_id)
    known_ids = [blue_ts_id, green_ts_id]
    _poll_until(
        lambda: _list_task_set_ids(ecs, cluster_name, service_name, known_ids),
        lambda ids: blue_ts_id not in ids,
        timeout_s=180,
        interval_s=5,
    )
    remaining_ids = _list_task_set_ids(ecs, cluster_name, service_name, known_ids)
    assert remaining_ids == [green_ts_id], (
        f"expected only the winning green task set {green_ts_id!r} to remain, got {remaining_ids!r}"
    )

    # The deleted (blue) task set must be independently unreadable, not merely absent from the
    # winner's list: DescribeTaskSets reports it as a failure rather than a describable task set.
    dead_lookup = ecs.describe_task_sets(cluster=cluster_name, service=service_name, taskSets=[blue_ts_id])
    assert dead_lookup["taskSets"] == [], (
        f"deleted task set {blue_ts_id!r} must not be describable any more, got {dead_lookup['taskSets']!r}"
    )
    assert len(dead_lookup.get("failures", [])) == 1, (
        f"expected exactly one DescribeTaskSets failure for the deleted task set, "
        f"got {dead_lookup.get('failures')!r}"
    )

    ecs.delete_service(cluster=cluster_name, service=service_name, force=True)


def _register_td(ecs, family, tag):
    return ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sleep", "3600"],
                "environment": [{"name": "COLOR", "value": tag}],
            }
        ],
        tags=_TAGS,
    )["taskDefinition"]["taskDefinitionArn"]


# ===== helpers =====
def _delete_cluster_once_drained(ecs, cluster, timeout_s=600.0, interval_s=10.0):
    """Delete the cluster once its services and tasks are gone; a draining service or a task that
    has not yet stopped blocks DeleteCluster."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ClusterNotFoundException":
                return
            if code not in ("ClusterContainsServicesException", "ClusterContainsTasksException"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"cluster {cluster} not deletable after {timeout_s:.0f}s: {code}")
        time.sleep(interval_s)


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _ensure_service_linked_role(ctx):
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise


def _create_service_with_retry(ecs, timeout_s=90.0, interval_s=10.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return ecs.create_service(**kwargs)
        except ClientError as e:
            msg = e.response["Error"].get("Message", "")
            if e.response["Error"]["Code"] == "InvalidParameterException" and "service linked role" in msg:
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _describe_task_set(ecs, cluster_name, service_name, task_set_id):
    resp = ecs.describe_task_sets(cluster=cluster_name, service=service_name, taskSets=[task_set_id])
    return resp["taskSets"][0]


def _list_task_set_ids(ecs, cluster_name, service_name, known_ids):
    resp = ecs.describe_task_sets(cluster=cluster_name, service=service_name, taskSets=known_ids)
    return sorted(ts["id"] for ts in resp["taskSets"])


def _wait_steady_state(ctx, cluster_name, service_name, task_set_id, timeout_s):
    ecs = ctx.client("ecs")
    status = _poll_until(
        lambda: _describe_task_set(ecs, cluster_name, service_name, task_set_id)["stabilityStatus"],
        lambda s: s == "STEADY_STATE",
        timeout_s=timeout_s,
        interval_s=8,
    )
    assert status == "STEADY_STATE", f"expected STEADY_STATE, got {status!r}"


def _fargate_network(ctx):
    """(subnet, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return net.subnet_ids[0], net.security_group_id


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
