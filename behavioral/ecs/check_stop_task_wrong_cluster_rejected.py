"""stop-task-wrong-cluster-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-task-wrong-cluster-rejected"
GROUP = "task-lifecycle"
SERVICES = ["ecs"]


def _fargate_network(ctx):
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _retire_task_definition(ecs, task_definition_arn: str) -> None:
    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition_arn)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=task_definition_arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[task_definition_arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {task_definition_arn} teardown failed: {failures}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopTask refuses a task ARN whose task lives in a different cluster than the one named,
    leaving the task running; StopTask against the task's own cluster stops it."""
    ecs = ctx.client("ecs")
    subnets, sg = _fargate_network(ctx)

    owning_cluster = ctx.unique_name("sim2real-behav-ecs-owner-cluster-")
    ecs.create_cluster(clusterName=owning_cluster, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=owning_cluster))

    other_cluster = ctx.unique_name("sim2real-behav-ecs-other-cluster-")
    ecs.create_cluster(clusterName=other_cluster, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=other_cluster))

    family = ctx.unique_name("sim2real-behav-ecs-owner-td-")
    td_arn = ecs.register_task_definition(
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
                "command": ["sh", "-c", "sleep 300"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    run_resp = ecs.run_task(
        cluster=owning_cluster,
        taskDefinition=td_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets,
                "securityGroups": [sg],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    assert run_resp["failures"] == [], f"RunTask reported failures: {run_resp['failures']}"
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=owning_cluster, task=task_arn))

    def _describe_in_owner():
        tasks = ecs.describe_tasks(cluster=owning_cluster, tasks=[task_arn])["tasks"]
        return tasks[0] if tasks else None

    running = _poll_until(
        _describe_in_owner, lambda t: t is not None and t["lastStatus"] == "RUNNING", timeout_s=180.0
    )
    assert running["lastStatus"] == "RUNNING", f"expected RUNNING, got {running['lastStatus']!r}"

    code, message = _error(lambda: ecs.stop_task(cluster=other_cluster, task=task_arn))
    assert code == "InvalidParameterException", f"unexpected error code: {code}"
    assert message == "Invalid identifier: cluster identifiers mismatch", (
        f"unexpected error message: {message!r}"
    )

    still_running = ecs.describe_tasks(cluster=owning_cluster, tasks=[task_arn])["tasks"][0]
    assert still_running["desiredStatus"] == "RUNNING", (
        f"StopTask against the wrong cluster must not change desiredStatus, "
        f"got {still_running['desiredStatus']!r}"
    )

    stopped_task = ecs.stop_task(cluster=owning_cluster, task=task_arn)["task"]
    assert stopped_task["desiredStatus"] == "STOPPED", (
        f"StopTask against the owning cluster must flip desiredStatus to STOPPED, "
        f"got {stopped_task['desiredStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
