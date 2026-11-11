"""container-health-check-transitions-healthy-and-unhealthy."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "container-health-check-transitions-healthy-and-unhealthy"
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
    task's ENI.

    A prerequisite is the check's job, not the account's. CreateService creates this role
    implicitly; RunTask does NOT, so in an account that has never used ECS every Fargate
    RunTask fails with InvalidParameterException "Unable to assume the service linked role".
    Already-exists (InvalidInput) is success, not an error condition.

    A freshly minted role is not assumable at once, and ECS reports that as the identical
    refusal as a missing role — so the wait for it to become assumable is a bounded retry
    around the first real use (RunTask), not a fixed sleep here: a fixed wait is either too
    short under load or wastes time once the role is already warm.

    No teardown is registered: the role is account-level, free and shared by every ECS
    workload, and DeleteServiceLinkedRole fails while any ECS resource still references it.
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


def _run_task_awaiting_slr(ecs, *, cluster, taskDefinition, launchType, count, networkConfiguration):
    """RunTask, retrying while ECS still reports the ECS service-linked role as unassumable.

    Bounded by a deadline: a role that is already warm returns on the first attempt, and one
    that was just created is retried only as long as it takes to become assumable.
    """
    deadline = time.monotonic() + 90
    while True:
        try:
            return ecs.run_task(
                cluster=cluster,
                taskDefinition=taskDefinition,
                launchType=launchType,
                count=count,
                networkConfiguration=networkConfiguration,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "")
            if (
                code == "InvalidParameterException"
                and "assume the service linked role" in message.lower()
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A container healthCheck runs inside the container and drives healthStatus: a passing probe
    gives HEALTHY (container and task), a failing one UNHEALTHY while the standalone task stays
    RUNNING, and a container with no healthCheck stays UNKNOWN."""
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
    probe = {"interval": 5, "timeout": 2, "retries": 2, "startPeriod": 10}

    def _register(defs: list[dict]) -> str:
        arn = ecs.register_task_definition(
            family=ctx.unique_name("sim2real-behav-ecs-taskdef-fg-"),
            containerDefinitions=defs,
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            cpu="256",
            memory="512",
        )["taskDefinition"]["taskDefinitionArn"]
        ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))
        ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=arn))
        return arn

    def _run(td_arn: str) -> str:
        resp = _run_task_awaiting_slr(
            ecs,
            cluster=cluster,
            taskDefinition=td_arn,
            launchType="FARGATE",
            count=1,
            networkConfiguration=net_cfg,
        )
        assert not resp.get("failures"), f"unexpected RunTask failures: {resp.get('failures')}"
        arn = resp["tasks"][0]["taskArn"]
        ctx.on_cleanup(
            lambda: ecs.stop_task(cluster=cluster, task=arn, reason="behavioral-cleanup")
        )
        return arn

    def _task(arn: str) -> dict:
        return ecs.describe_tasks(cluster=cluster, tasks=[arn])["tasks"][0]

    def _container(task: dict, name: str) -> dict:
        for c in task.get("containers", []):
            if c.get("name") == name:
                return c
        raise AssertionError(f"container {name!r} missing from {task.get('containers')}")

    healthy_td = _register(
        [
            {
                "name": "app",
                "image": image,
                "essential": True,
                "command": ["sh", "-c", "sleep 900"],
                "healthCheck": {"command": ["CMD-SHELL", "exit 0"], **probe},
            }
        ]
    )
    healthy_arn = _run(healthy_td)
    healthy = _poll_until(
        lambda: _task(healthy_arn),
        lambda t: _container(t, "app").get("healthStatus") == "HEALTHY",
        timeout_s=600,
        interval_s=10,
        description="the passing container health check drives the container to HEALTHY",
    )
    assert healthy.get("healthStatus") == "HEALTHY", (
        "a task whose only essential container is HEALTHY must itself report HEALTHY, got "
        f"{healthy.get('healthStatus')!r}"
    )
    assert healthy["lastStatus"] == "RUNNING", (
        f"expected lastStatus RUNNING for a task with a HEALTHY container, got "
        f"{healthy['lastStatus']!r}"
    )

    unhealthy_td = _register(
        [
            {
                "name": "app",
                "image": image,
                "essential": True,
                "command": ["sh", "-c", "sleep 900"],
                "healthCheck": {"command": ["CMD-SHELL", "exit 1"], **probe},
            },
            {
                "name": "nohc",
                "image": image,
                "essential": False,
                "command": ["sh", "-c", "sleep 900"],
            },
        ]
    )
    unhealthy_arn = _run(unhealthy_td)
    unhealthy = _poll_until(
        lambda: _task(unhealthy_arn),
        lambda t: _container(t, "app").get("healthStatus") == "UNHEALTHY",
        timeout_s=600,
        interval_s=10,
        description="the failing container health check drives the container to UNHEALTHY",
    )
    assert _container(unhealthy, "app").get("healthStatus") == "UNHEALTHY", (
        f"expected UNHEALTHY, got {_container(unhealthy, 'app')}"
    )
    assert _container(unhealthy, "nohc").get("healthStatus") == "UNKNOWN", (
        "a container with no healthCheck defined must report healthStatus UNKNOWN, got "
        f"{_container(unhealthy, 'nohc')}"
    )
    assert unhealthy["lastStatus"] == "RUNNING", (
        "a standalone (non-service) task must NOT be killed for being unhealthy, got lastStatus="
        f"{unhealthy['lastStatus']!r} stoppedReason={unhealthy.get('stoppedReason')!r}"
    )
    round_tripped = ecs.describe_task_definition(taskDefinition=unhealthy_td)["taskDefinition"]
    app_def = next(c for c in round_tripped["containerDefinitions"] if c["name"] == "app")
    assert app_def["healthCheck"]["command"] == ["CMD-SHELL", "exit 1"], (
        f"expected round-tripped healthCheck.command ['CMD-SHELL', 'exit 1'], got "
        f"{app_def['healthCheck'].get('command')!r}"
    )
    assert app_def["healthCheck"]["interval"] == 5, (
        f"expected round-tripped healthCheck.interval 5, got "
        f"{app_def['healthCheck'].get('interval')!r}"
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
