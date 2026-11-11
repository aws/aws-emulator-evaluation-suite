"""run-task-fargate-lifecycle-to-stopped."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "run-task-fargate-lifecycle-to-stopped"
GROUP = "state"
SERVICES = ["ecs"]

_ECS_TAGS = [{"key": "sim2real", "value": "true"}]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask on Fargate progresses to RUNNING; StopTask drives it to STOPPED with
    stopCode=UserInitiated and the supplied stoppedReason preserved."""
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx)
    subnets, sg_id = _fargate_network(ctx)
    task_def = _register_fargate_task_def(ctx, ctx.unique_name("sim2real-ecs-td-"))

    run_resp = ecs.run_task(
        cluster=cluster["clusterArn"],
        taskDefinition=task_def["taskDefinitionArn"],
        launchType="FARGATE",
        count=1,
        tags=_ECS_TAGS,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets,
                "securityGroups": [sg_id] if sg_id else [],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    assert not run_resp.get("failures"), f"unexpected RunTask failures: {run_resp.get('failures')}"
    assert len(run_resp["tasks"]) == 1, f"expected exactly 1 task, got {len(run_resp['tasks'])}"
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(
        lambda: ecs.stop_task(cluster=cluster["clusterArn"], task=task_arn, reason="test-cleanup")
    )

    def _describe():
        return ecs.describe_tasks(cluster=cluster["clusterArn"], tasks=[task_arn])["tasks"][0]

    running = _poll_until(
        _describe,
        lambda t: t["lastStatus"] in ("RUNNING", "STOPPED"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert running["lastStatus"] == "RUNNING", (
        f"task never reached RUNNING (stopped early: {running.get('stoppedReason')})"
    )
    assert running["desiredStatus"] == "RUNNING", (
        f"expected desiredStatus RUNNING, got {running['desiredStatus']}"
    )
    assert running["containers"], "expected container status entries once RUNNING"

    stop_reason = "sim2real-behavioral-stop"
    ecs.stop_task(cluster=cluster["clusterArn"], task=task_arn, reason=stop_reason)

    stopped = _poll_until(_describe, lambda t: t["lastStatus"] == "STOPPED", timeout_s=240.0, interval_s=10.0)
    assert stopped["desiredStatus"] == "STOPPED", (
        f"expected desiredStatus STOPPED, got {stopped['desiredStatus']}"
    )
    assert stopped["stopCode"] == "UserInitiated", f"expected UserInitiated, got {stopped.get('stopCode')}"
    assert stop_reason in (stopped.get("stoppedReason") or ""), (
        f"stoppedReason {stopped.get('stoppedReason')!r} did not preserve our reason"
    )


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return list(net.subnet_ids[:2]), net.security_group_id


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-cluster-")
    cluster = ecs.create_cluster(clusterName=name, tags=_ECS_TAGS)["cluster"]

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
        tags=_ECS_TAGS,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": command or ["sleep", "600"],
            }
        ],
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
