"""run-task-environment-override-injected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "run-task-environment-override-injected"
GROUP = 'task'
SERVICES = ['ecs']

# ===== helpers =====


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


def _refusal(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because a target accepting what AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A containerOverrides environment value reaches the container process and replaces the task
    definition's value (exit code 17, not 1), and an override naming an unknown container is
    rejected with InvalidParameterException and launches no task."""
    ecs = ctx.client("ecs")
    cluster = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=cluster)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster))

    td_arn = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-fg-"),
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "environment": [{"name": "SIM2REAL_EXIT", "value": "1"}],
                "command": ["sh", "-c", "exit ${SIM2REAL_EXIT}"],
            }
        ],
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td_arn))

    subnets, sg = _fargate_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": subnets[:1],
            "securityGroups": [sg],
            "assignPublicIp": "ENABLED",
        }
    }

    # ---- deep negative: an override for a container that does not exist ----
    before = ecs.list_tasks(cluster=cluster)["taskArns"]
    assert before == [], f"the cluster must start with no tasks, got {before}"
    code, message = _refusal(
        lambda: ecs.run_task(
            cluster=cluster,
            taskDefinition=td_arn,
            launchType="FARGATE",
            count=1,
            networkConfiguration=net_cfg,
            overrides={
                "containerOverrides": [
                    {
                        "name": "not-in-this-task-definition",
                        "environment": [{"name": "SIM2REAL_EXIT", "value": "0"}],
                    }
                ]
            },
        )
    )
    assert code == "InvalidParameterException", (
        "an override naming a container absent from the task definition must be rejected with "
        f"InvalidParameterException, got {code!r}"
    )
    assert message == "Override for container named not-in-this-task-definition is not a container in the TaskDefinition.", f"refusal message {message!r}"
    assert ecs.list_tasks(cluster=cluster)["taskArns"] == [], (
        f"the rejected RunTask must not have created a task, got {ecs.list_tasks(cluster=cluster)['taskArns']}"
    )

    def _run(overrides=None) -> str:
        kwargs = {"overrides": overrides} if overrides else {}
        resp = ecs.run_task(
            cluster=cluster,
            taskDefinition=td_arn,
            launchType="FARGATE",
            count=1,
            networkConfiguration=net_cfg,
            **kwargs,
        )
        assert not resp.get("failures"), f"unexpected RunTask failures: {resp.get('failures')}"
        arn = resp["tasks"][0]["taskArn"]
        ctx.on_cleanup(
            lambda: ecs.stop_task(cluster=cluster, task=arn, reason="behavioral-cleanup")
        )
        return arn

    baseline_arn = _run()
    override_arn = _run(
        {
            "containerOverrides": [
                {"name": "app", "environment": [{"name": "SIM2REAL_EXIT", "value": "17"}]}
            ]
        }
    )

    def _finished(task_arn: str) -> dict:
        task = _poll_until(
            lambda: ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"][0],
            lambda t: t["lastStatus"] == "STOPPED",
            timeout_s=600,
            interval_s=10,
            description="the task runs its command to completion",
        )
        return next(c for c in task.get("containers", []) if c["name"] == "app")

    baseline = _finished(baseline_arn)
    assert baseline.get("exitCode") == 1, (
        "without an override the task definition's own SIM2REAL_EXIT=1 must reach the process, got "
        f"{baseline}"
    )

    overridden = _finished(override_arn)
    assert overridden.get("exitCode") == 17, (
        "the container override's SIM2REAL_EXIT=17 must be injected into the process and REPLACE "
        f"the task definition's value, got {overridden}"
    )

    echoed = ecs.describe_tasks(cluster=cluster, tasks=[override_arn])["tasks"][0]
    echoed_env = next(
        co.get("environment", [])
        for co in echoed.get("overrides", {}).get("containerOverrides", [])
        if co.get("name") == "app"
    )
    assert {"name": "SIM2REAL_EXIT", "value": "17"} in echoed_env, (
        f"the task record must retain the environment override it was launched with, got {echoed_env}"
    )


def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
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
