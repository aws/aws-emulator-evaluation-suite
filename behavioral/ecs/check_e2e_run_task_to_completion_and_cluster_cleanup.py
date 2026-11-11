"""e2e-run-task-to-completion-and-cluster-cleanup."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-run-task-to-completion-and-cluster-cleanup"
GROUP = "e2e"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A standalone one-shot Fargate task naturally exits to STOPPED with a zero exit code, the
    cluster's running-task count drops to zero, and the now-empty cluster deletes cleanly."""
    ecs = ctx.client("ecs")
    subnet_ids, sg_id = _default_networking(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-e2e-run-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_cluster(cluster=cluster_name)))

    family = ctx.unique_name("sim2real-ecs-e2e-run-td-")
    td = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "runner",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sh", "-c", "echo sim2real-hello && exit 0"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    run_resp = ecs.run_task(
        cluster=cluster_name,
        taskDefinition=td_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnet_ids,
                "securityGroups": [sg_id],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    assert not run_resp["failures"], f"RunTask reported failures: {run_resp['failures']}"
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.stop_task(cluster=cluster_name, task=task_arn)))

    def _describe_task():
        return ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])["tasks"][0]

    stopped = _poll_until(_describe_task, lambda t: t["lastStatus"] == "STOPPED", timeout_s=150.0, interval_s=5.0)
    container = stopped["containers"][0]
    assert stopped.get("stopCode") == "EssentialContainerExited", (
        f"unexpected stopCode={stopped.get('stopCode')!r} stoppedReason={stopped.get('stoppedReason')!r} "
        f"container={container!r}"
    )
    assert container["exitCode"] == 0, (
        f"unexpected exitCode={container.get('exitCode')!r} reason={container.get('reason')!r} "
        f"stoppedReason={stopped.get('stoppedReason')!r}"
    )

    def _cluster_counts():
        return ecs.describe_clusters(clusters=[cluster_name])["clusters"][0]

    _poll_until(
        _cluster_counts,
        lambda c: c["runningTasksCount"] == 0 and c["pendingTasksCount"] == 0,
        timeout_s=120.0,
        interval_s=5.0,
    )

    delete_resp = ecs.delete_cluster(cluster=cluster_name)["cluster"]
    assert delete_resp["status"] == "INACTIVE", f"expected INACTIVE on delete, got {delete_resp['status']!r}"

    def _cluster_status_after_delete():
        rows = ecs.describe_clusters(clusters=[cluster_name])["clusters"]
        return rows[0]["status"] if rows else "GONE"

    final_status = _poll_until(
        _cluster_status_after_delete, lambda s: s in ("INACTIVE", "GONE"), timeout_s=30.0, interval_s=3.0
    )
    assert final_status in ("INACTIVE", "GONE"), (
        f"independent describe_clusters read did not settle to INACTIVE/GONE after delete, got {final_status!r}"
    )


# ===== helpers =====

def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _default_networking(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region; required to build the awsvpc "
            "networkConfiguration (subnets + security group) this check needs"
        )
    vpc = vpcs[0]
    vpc_id = vpc["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    return subnet_ids, sg_id


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
