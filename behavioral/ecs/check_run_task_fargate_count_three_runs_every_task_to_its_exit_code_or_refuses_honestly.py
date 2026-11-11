"""run-task-fargate-count-three-runs-every-task-to-its-exit-code-or-refuses-honestly."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-task-fargate-count-three-runs-every-task-to-its-exit-code-or-refuses-honestly"
GROUP = "task-lifecycle"
SERVICES = ["ecs"]

_EXIT_CODE = 7
_COUNT = 3
_STOP_BUDGET_S = 90


@tags("axis:happy-path", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Fargate RunTask of count 3 whose container exits 7 either really runs all three (each STOPS
    with EssentialContainerExited and exitCode 7, and the cluster's STOPPED listing names exactly those
    three) or refuses with a structured reason and starts nothing; a task faked as running fails."""
    _start_budget(ctx)
    ecs = ctx.client("ecs")

    cluster = ctx.unique_name("sim2real-behav-honest3-")
    ecs.create_cluster(clusterName=cluster, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))

    td_arn = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-honest3-"),
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[{
            "name": "app",
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "essential": True,
            "command": ["sh", "-c", f"exit {_EXIT_CODE}"],
        }],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _deregister(ecs, td_arn))
    started_by = ctx.unique_name("s2r-")

    try:
        resp = ecs.run_task(
            cluster=cluster, taskDefinition=td_arn, count=_COUNT, launchType="FARGATE",
            startedBy=started_by, networkConfiguration=_network_configuration(ctx),
        )
    except ClientError as exc:
        _honest_refusal(ecs, cluster, exc=exc)
        return
    tasks = resp.get("tasks") or []
    failures = resp.get("failures") or []
    if not tasks:
        _honest_refusal(ecs, cluster, failures=failures)
        return

    arns = sorted(t["taskArn"] for t in tasks)
    for arn in arns:
        ctx.on_cleanup(lambda a=arn: _stop_task(ecs, cluster, a))
    assert (len(set(arns)), failures) == (_COUNT, []), (
        f"RunTask count={_COUNT}: expected {_COUNT} distinct tasks and no failures, got {len(set(arns))} "
        f"tasks and failures {failures!r}"
    )
    assert all(t.get("startedBy") == started_by for t in tasks), "RunTask tasks must carry the startedBy value"

    deadline = time.monotonic() + _bounded(_STOP_BUDGET_S)
    described = tasks
    while time.monotonic() < deadline:
        described = ecs.describe_tasks(cluster=cluster, tasks=arns)["tasks"]
        assert len(described) == _COUNT, f"DescribeTasks knows {len(described)} of the {_COUNT} accepted tasks"
        if all(t.get("lastStatus") == "STOPPED" for t in described):
            break
        time.sleep(5)
    statuses = sorted(t.get("lastStatus") for t in described)
    assert statuses == ["STOPPED"] * _COUNT, (
        f"every accepted task must stop within {_STOP_BUDGET_S}s since its only container exits "
        f"{_EXIT_CODE} at once, got lastStatus {statuses!r}: a task reported RUNNING that runs nothing is fake success"
    )
    for t in described:
        containers = t.get("containers") or []
        got = (t.get("stopCode"), [c.get("exitCode") for c in containers])
        assert got == ("EssentialContainerExited", [_EXIT_CODE]), (
            f"stopped task (stopCode, container exit codes): expected ('EssentialContainerExited', [{_EXIT_CODE}]), "
            f"got {got!r} (stoppedReason={t.get('stoppedReason')!r})"
        )

    # ListTasks takes one filter here: desiredStatus on the check's own cluster (startedBy must be
    # used alone and lists only RUNNING tasks); startedBy is graded on DescribeTasks.
    listed = sorted(ecs.list_tasks(cluster=cluster, desiredStatus="STOPPED").get("taskArns", []))
    assert listed == arns, f"ListTasks(desiredStatus=STOPPED) must name exactly the {_COUNT} tasks, got {len(listed)}"
    tags = sorted(t.get("startedBy") for t in described)
    assert tags == [started_by] * _COUNT, "DescribeTasks must report the RunTask startedBy value on every task"


# ===== helpers =====


#: The runner's deadline for this check (monotonic clock), set as run() starts.
_RUN_END: dict = {}


def _bounded(timeout_s: float) -> float:
    """``timeout_s`` cut to the time the runner leaves this check, so a wait fails with its own
    last observation rather than the runner's timeout."""
    end = _RUN_END.get("t")
    return timeout_s if end is None else max(1.0, min(timeout_s, end - time.monotonic() - 3.0))


def _start_budget(ctx) -> None:
    left = ctx.time_left()
    _RUN_END["t"] = None if left is None else time.monotonic() + left



def _honest_refusal(ecs, cluster, exc=None, failures=None) -> None:
    """An honest refusal: a ClientError with a code, a 4xx/5xx status and a message, or HTTP 200
    with failures that each carry a reason; either way no task is started."""
    if exc is not None:
        err = exc.response.get("Error", {})
        status = exc.response["ResponseMetadata"].get("HTTPStatusCode")
        assert err.get("Code"), f"RunTask was refused without an error code: {exc.response!r}"
        assert isinstance(status, int) and 400 <= status < 600, f"refusal was HTTP {status!r}"
        assert (err.get("Message") or "").strip(), f"RunTask refusal {err['Code']} has no message"
    else:
        assert failures, "RunTask returned neither a task nor a failure"
        for f in failures:
            assert (f.get("reason") or "").strip(), f"RunTask failure has no reason: {f!r}"
    _assert_no_task(ecs, cluster)


def _assert_no_task(ecs, cluster) -> None:
    for status in ("RUNNING", "PENDING", "STOPPED"):
        arns = ecs.list_tasks(cluster=cluster, desiredStatus=status).get("taskArns", [])
        assert not arns, f"RunTask was refused yet ListTasks({status}) shows {arns!r}"


def _network_configuration(ctx) -> dict:
    """The run's network: its public subnets and group, with a public address for the image pull."""
    net = ctx.network()
    return {"awsvpcConfiguration": {
        "subnets": net.subnet_ids[:2], "securityGroups": [net.security_group_id], "assignPublicIp": "ENABLED",
    }}


def _stop_task(ecs, cluster, task_arn) -> None:
    try:
        ecs.stop_task(cluster=cluster, task=task_arn, reason="sim2real teardown")
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("InvalidParameterException", "ClusterNotFoundException"):
            raise
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        tasks = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        if not tasks or tasks[0].get("lastStatus") == "STOPPED":
            return
        time.sleep(5)
    raise AssertionError(f"task {task_arn} did not stop within the teardown budget")


def _deregister(ecs, td_arn) -> None:
    try:
        ecs.deregister_task_definition(taskDefinition=td_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ClientException":
            raise
    try:
        ecs.delete_task_definitions(taskDefinitions=[td_arn])
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ClientException", "InvalidParameterException"):
            raise


def _delete_cluster(ecs, cluster) -> None:
    try:
        ecs.delete_cluster(cluster=cluster)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
