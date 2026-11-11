"""run-task-runs-or-refuses-honestly."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-task-runs-or-refuses-honestly"
GROUP = "task-lifecycle"
SERVICES = ["ecs"]

_EXIT_CODE = 3
_STOP_BUDGET_S = 200


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RunTask of a container that exits 3 either really runs it (the task STOPS with exitCode 3)
    or refuses with a structured reason and starts nothing; a task faked as running fails."""
    ecs = ctx.client("ecs")

    cluster = ctx.unique_name("sim2real-behav-honest-")
    ecs.create_cluster(clusterName=cluster, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))

    td_arn = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-honest-"),
        networkMode="bridge",
        containerDefinitions=[{
            "name": "app",
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "essential": True,
            "memory": 128,
            "command": ["sh", "-c", f"exit {_EXIT_CODE}"],
        }],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _deregister(ecs, td_arn))

    try:
        resp = ecs.run_task(cluster=cluster, taskDefinition=td_arn, count=1)
    except ClientError as e:
        err = e.response.get("Error", {})
        status = e.response["ResponseMetadata"].get("HTTPStatusCode")
        assert err.get("Code"), f"RunTask was refused without an error code: {e.response!r}"
        assert isinstance(status, int) and 400 <= status < 600, f"refusal was HTTP {status!r}"
        assert (err.get("Message") or "").strip(), f"RunTask refusal {err['Code']} has no message"
        _assert_no_task(ecs, cluster)
        return

    tasks = resp.get("tasks") or []
    failures = resp.get("failures") or []
    if not tasks:
        # AWS's own refusal form: HTTP 200 with a structured failure per task it could not place.
        assert failures, f"RunTask returned neither a task nor a failure: {resp!r}"
        for f in failures:
            assert (f.get("reason") or "").strip(), f"RunTask failure has no reason: {f!r}"
        _assert_no_task(ecs, cluster)
        return

    assert len(tasks) == 1, f"RunTask count=1 returned {len(tasks)} tasks"
    task_arn = tasks[0]["taskArn"]
    ctx.on_cleanup(lambda: _stop_task(ecs, cluster, task_arn))
    deadline = time.monotonic() + _STOP_BUDGET_S
    task = tasks[0]
    while task.get("lastStatus") != "STOPPED" and time.monotonic() < deadline:
        time.sleep(5)
        described = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"]
        assert described, f"DescribeTasks no longer knows the accepted task {task_arn}"
        task = described[0]
    assert task.get("lastStatus") == "STOPPED", (
        f"the accepted task never stopped within {_STOP_BUDGET_S}s although its only container "
        f"exits {_EXIT_CODE} at once: lastStatus={task.get('lastStatus')!r}. A task reported "
        f"RUNNING that runs nothing is fake success"
    )
    containers = task.get("containers") or []
    assert containers, f"the stopped task reports no containers: {task!r}"
    exit_code = containers[0].get("exitCode")
    assert exit_code == _EXIT_CODE, (
        f"the container exited {exit_code!r}, expected {_EXIT_CODE}: the command did not run "
        f"(reason={containers[0].get('reason')!r}, stoppedReason={task.get('stoppedReason')!r})"
    )


# ===== helpers =====


def _assert_no_task(ecs, cluster) -> None:
    for status in ("RUNNING", "PENDING", "STOPPED"):
        arns = ecs.list_tasks(cluster=cluster, desiredStatus=status).get("taskArns", [])
        assert not arns, f"RunTask was refused yet ListTasks({status}) shows {arns!r}"


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
