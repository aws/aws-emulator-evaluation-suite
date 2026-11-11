"""run-task-with-an-unpullable-image-reports-failed-to-start-not-running."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-task-with-an-unpullable-image-reports-failed-to-start-not-running"
GROUP = "task-lifecycle"
SERVICES = ["ecs"]

_STOP_BUDGET_S = 150
#: Runs of the control task while the new execution role propagates to ecs-tasks.
_ROLE_ATTEMPTS = 4
#: Bounded wait for RunTask to accept the just-created execution role.
_ROLE_PROPAGATION_S = 120
_CONTROL_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"
_TRUST_ECS_TASKS = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Fargate task naming a tag absent from the check's own private ECR repo either is refused
    honestly (structured reason, nothing started) or STOPS TaskFailedToStart with a reason naming
    the tag, no startedAt and no exit code, while a pullable control exits 0."""
    _start_budget(ctx)
    ecs = ctx.client("ecs")
    partition = _partition(ctx)
    exec_role = _execution_role(ctx, partition)
    repo_uri = _repository(ctx)

    cluster = ctx.unique_name("sim2real-behav-nopull-")
    ecs.create_cluster(clusterName=cluster, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))

    def _td(image, command):
        arn = ecs.register_task_definition(
            family=ctx.unique_name("sim2real-behav-nopull-"),
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            cpu="256",
            memory="512",
            executionRoleArn=exec_role,
            containerDefinitions=[{"name": "app", "image": image, "essential": True, "command": command}],
            tags=[{"key": "sim2real", "value": CHECK}],
        )["taskDefinition"]["taskDefinitionArn"]
        ctx.on_cleanup(lambda: _deregister(ecs, arn))
        return arn

    # Positive control: the same role and network start a pullable image that exits 0. Its runs
    # also wait out the new role's propagation, a bounded retry on the role's first use.
    control_td = _td(_CONTROL_IMAGE, ["sh", "-c", "exit 0"])
    for attempt in range(1, _ROLE_ATTEMPTS + 1):
        control = _run_to_stopped(ctx, ecs, cluster, control_td)
        if control is None:
            return  # an honest refusal that starts nothing covers the whole check
        if control.get("stopCode") != "TaskFailedToStart" or attempt == _ROLE_ATTEMPTS:
            break
    got = (control.get("stopCode"), [c.get("exitCode") for c in control.get("containers") or []])
    assert got == ("EssentialContainerExited", [0]), (
        f"control task (stopCode, exit codes): expected ('EssentialContainerExited', [0]), got {got!r} "
        f"(stoppedReason={(control.get('stoppedReason') or '')[:160]!r})"
    )

    missing_tag = ctx.unique_name("absent-")
    task = _run_to_stopped(ctx, ecs, cluster, _td(f"{repo_uri}:{missing_tag}", ["sh", "-c", "exit 0"]))
    if task is None:
        return  # refused honestly: structured reason, no task started
    reason = task.get("stoppedReason") or ""
    got = (task.get("stopCode"), missing_tag in reason)
    assert got == ("TaskFailedToStart", True), (
        f"task naming an absent tag (stopCode, reason names the tag): expected ('TaskFailedToStart', True), "
        f"got {got!r} with stoppedReason {reason[:200]!r}"
    )
    codes = [c.get("exitCode") for c in task.get("containers") or []]
    assert codes == [None], f"a container that never started reports no exit code, got {codes!r}"
    assert task.get("startedAt") is None, f"a task that failed to start reports no startedAt, got {task.get('startedAt')!r}"


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



def _run_to_stopped(ctx, ecs, cluster, td_arn) -> dict:
    """RunTask one Fargate task and poll it to STOPPED; None after an honest refusal (graded)."""
    # A just-created execution role can be refused until it propagates: a bounded retry on its
    # first use, which a target that is consistent at once passes on the first try.
    deadline = time.monotonic() + _bounded(_ROLE_PROPAGATION_S)
    while True:
        try:
            resp = ecs.run_task(
                cluster=cluster, taskDefinition=td_arn, count=1, launchType="FARGATE",
                networkConfiguration=_network_configuration(ctx),
            )
            break
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message") or ""
            if not msg.startswith("ECS was unable to assume the role") or time.monotonic() >= deadline:
                _honest_refusal(ecs, cluster, exc=exc)
                return None
        time.sleep(5)
    tasks, failures = resp.get("tasks") or [], resp.get("failures") or []
    if not tasks:
        _honest_refusal(ecs, cluster, failures=failures)
        return None
    assert (len(tasks), failures) == (1, []), f"RunTask count=1: expected one task and no failures, got {len(tasks)} and {failures!r}"
    task_arn = tasks[0]["taskArn"]
    ctx.on_cleanup(lambda: _stop_task(ecs, cluster, task_arn))
    deadline = time.monotonic() + _bounded(_STOP_BUDGET_S)
    task = tasks[0]
    while time.monotonic() < deadline:
        if task.get("lastStatus") == "STOPPED":
            return task
        time.sleep(5)
        described = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"]
        assert described, f"DescribeTasks no longer knows the accepted task {task_arn}"
        task = described[0]
    raise AssertionError(
        f"the task did not stop within {_STOP_BUDGET_S}s (lastStatus={task.get('lastStatus')!r}): a task "
        "reported RUNNING without its image is fake success"
    )


def _execution_role(ctx, partition: str) -> str:
    """A task execution role of the check's own, trusted by ecs-tasks, with the managed pull policy."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-nopull-exec-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST_ECS_TASKS),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_codes(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    policy = f"arn:{partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(lambda: _ignore_codes(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy), "NoSuchEntity"))
    return arn


def _repository(ctx) -> str:
    """An empty private ECR repository of the check's own; force-deleted on cleanup."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-nopull-repo-")
    repo = ecr.create_repository(repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}])["repository"]
    ctx.on_cleanup(lambda: _ignore_codes(
        lambda: ecr.delete_repository(repositoryName=name, force=True), "RepositoryNotFoundException"))
    return repo["repositoryUri"]


def _ignore_codes(fn, *codes) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _partition(ctx) -> str:
    """The caller's partition, taken from its own ARN."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], f"GetCallerIdentity Arn {arn!r} names no partition"
    return parts[1]


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
