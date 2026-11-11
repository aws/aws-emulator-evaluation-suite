"""container-depends-on-success-gates-dependent-start."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "container-depends-on-success-gates-dependent-start"
GROUP = 'task-lifecycle'
SERVICES = ['ecs']

def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


def _ensure_ecs_slr(ctx):
    """Create AWSServiceRoleForECS, the service-linked role ECS assumes to attach an awsvpc
    task's ENI, and wait for it to become assumable.

    A prerequisite is the check's job, not the account's. CreateService creates this role
    implicitly; RunTask does NOT, so in an account that has never used ECS every Fargate
    RunTask fails with InvalidParameterException "Unable to assume the service linked role".
    Already-exists (InvalidInput) is success, not an error condition.

    No teardown is registered: the role is account-level, free and shared by every ECS
    workload, and DeleteServiceLinkedRole fails while any ECS resource still references it.

    A freshly minted service-linked role is not assumable at once; ECS reports that as the same
    "Unable to assume the service linked role" refusal as a missing one. There is no read that
    tells us the role is ready, so ``_run`` below retries RunTask itself on that specific
    failure instead of guessing a fixed wait here.
    """
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        if code not in ("InvalidInput", "InvalidInputException") or message != (
            "Service role name AWSServiceRoleForECS has been taken in this account, please try a different suffix."
        ):
            raise AssertionError(f"cannot create the ECS service-linked role: {exc}") from exc


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """dependsOn condition SUCCESS gates the dependent's start: when init exits 0, app runs and
    reports its own exit code 5; when init exits 1, app never runs (no exitCode) while init reports
    1, so a target that starts every container at once fails."""
    ecs = ctx.client("ecs")
    cluster = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=cluster)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster))
    _ensure_ecs_slr(ctx)
    subnets, sg = _fargate_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": subnets[:1],
            "securityGroups": [sg],
            "assignPublicIp": "ENABLED",
        }
    }
    image = "public.ecr.aws/docker/library/busybox:1.36"

    def _register(init_exit: int) -> str:
        arn = ecs.register_task_definition(
            family=ctx.unique_name("sim2real-behav-ecs-taskdef-fg-"),
            containerDefinitions=[
                {
                    "name": "init",
                    "image": image,
                    "essential": False,
                    "command": ["sh", "-c", f"sleep 3; exit {init_exit}"],
                },
                {
                    "name": "app",
                    "image": image,
                    "essential": True,
                    "command": ["sh", "-c", "exit 5"],
                    "dependsOn": [{"containerName": "init", "condition": "SUCCESS"}],
                },
            ],
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            cpu="256",
            memory="512",
        )["taskDefinition"]["taskDefinitionArn"]
        ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))
        ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=arn))
        return arn

    def _run(td_arn: str) -> str:
        # A just-created ECS service-linked role is not assumable at once (see
        # _ensure_ecs_slr); RunTask reports that as a launch failure rather than an API
        # error, so retry ONLY that specific, bounded reason rather than sleeping blind.
        deadline = time.monotonic() + 60
        while True:
            resp = ecs.run_task(
                cluster=cluster,
                taskDefinition=td_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration=net_cfg,
            )
            failures = resp.get("failures") or []
            if failures:
                detail = " ".join(f.get("reason", "") + " " + f.get("detail", "") for f in failures)
                if "assume the service linked role" in detail.lower() and time.monotonic() < deadline:
                    time.sleep(5)
                    continue
            assert not failures, f"unexpected RunTask failures: {failures}"
            break
        arn = resp["tasks"][0]["taskArn"]
        ctx.on_cleanup(
            lambda: ecs.stop_task(cluster=cluster, task=arn, reason="behavioral-cleanup")
        )
        return arn

    def _stopped(task_arn: str) -> dict:
        # A just-started task can be absent from DescribeTasks (reported under failures) for a
        # moment; that reads as not yet stopped.
        return _poll_until(
            lambda: next(iter(ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"]), None),
            lambda t: t is not None and t["lastStatus"] == "STOPPED",
            timeout_s=600,
            interval_s=10,
            description="the multi-container task reaches STOPPED",
        )

    def _container(task: dict, name: str) -> dict:
        for c in task.get("containers", []):
            if c.get("name") == name:
                return c
        raise AssertionError(f"container {name!r} missing from {task.get('containers')}")

    # ---- dependency satisfied: the gate opens and app really runs ----
    ok_task = _stopped(_run(_register(0)))
    assert _container(ok_task, "init").get("exitCode") == 0, _container(ok_task, "init")
    app_ok = _container(ok_task, "app")
    assert app_ok.get("exitCode") == 5, (
        "with its SUCCESS dependency satisfied, app's own process must have run and exited 5, got "
        f"{app_ok}"
    )
    assert _container(ok_task, "init").get("lastStatus") == "STOPPED", _container(ok_task, "init")

    # ---- dependency violated: app must never start (effect absent) ----
    gated_task = _stopped(_run(_register(1)))
    init_bad = _container(gated_task, "init")
    assert init_bad.get("exitCode") == 1, (
        f"the init container must report its own failing exit code, got {init_bad}"
    )
    app_gated = _container(gated_task, "app")
    assert app_gated.get("exitCode") is None, (
        "app must NEVER have run once its SUCCESS dependency failed — an exitCode here means the "
        f"runtime ignored dependsOn, got {app_gated}"
    )
    assert app_gated.get("lastStatus") == "STOPPED", (
        f"the ungated container must end up STOPPED, got {app_gated}"
    )
    assert gated_task.get("stoppedReason"), (
        f"the task must record why it stopped, got {gated_task.get('stoppedReason')!r}"
    )


def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=780.0, interval_s=2.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services, tasks or container instances remain, and a task's
    ENI stays in the shared network until the task has stopped, which keeps the network from
    being deleted.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s

    def arns(op, key, **kw):
        return [a for page in ecs.get_paginator(op).paginate(cluster=cluster, **kw) for a in page.get(key, [])]

    try:
        services = arns("list_services", "serviceArns")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ClusterNotFoundException":
            return
        raise
    for service in services:
        for call in (
            lambda s=service: ecs.update_service(cluster=cluster, service=s, desiredCount=0),
            lambda s=service: ecs.delete_service(cluster=cluster, service=s, force=True),
        ):
            try:
                call()
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("ServiceNotFoundException", "ServiceNotActiveException"):
                    raise
    while True:
        for task in arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            try:
                ecs.stop_task(cluster=cluster, task=task, reason="sim2real teardown")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                    raise
        stopping = arns("list_tasks", "taskArns", desiredStatus="STOPPED")
        live = []
        for i in range(0, len(stopping), 100):
            live += [t for t in ecs.describe_tasks(cluster=cluster, tasks=stopping[i:i + 100])["tasks"]
                     if t.get("lastStatus") != "STOPPED"]
        if not live and not arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{len(live)} task(s) in {cluster} still not STOPPED after {timeout_s:.0f}s")
        time.sleep(interval_s)
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code == "ClusterContainsContainerInstancesException":
                for instance in arns("list_container_instances", "containerInstanceArns"):
                    try:
                        ecs.deregister_container_instance(cluster=cluster, containerInstance=instance, force=True)
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                            raise
            elif code not in (
                "ClusterContainsTasksException",
                "ClusterContainsServicesException",
                "UpdateInProgressException",
                "ResourceInUseException",
            ):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
