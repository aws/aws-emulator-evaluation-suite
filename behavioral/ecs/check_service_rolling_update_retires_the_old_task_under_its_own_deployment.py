"""service-rolling-update-retires-the-old-task-under-its-own-deployment."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-rolling-update-retires-the-old-task-under-its-own-deployment"
GROUP = "service-deployment"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A task-definition update rolls a 1-task service onto a new deployment: the old task stops,
    attributed to the old deployment, the new one starts under the new, and the events say so.
    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-type-ecs.html
    """
    ecs = ctx.client("ecs")
    tok = ctx.unique_name("sim2real-behav-ecs-")
    _cluster(ctx, tok)
    td1 = _task_def(ctx, tok, "sleep 3600")
    name = f"{tok}-svc"
    old_dep = _service(ctx, tok, name, td1, 1)["deployments"][0]["id"]
    _poll(lambda: _describe(ctx, tok, name), lambda s: _settled(s, td1, 1),
          description="the first deployment COMPLETED with 1 RUNNING task")
    old_arns = _tasks(ctx, tok, name, "RUNNING")
    assert len(old_arns) == 1, f"one RUNNING task before the update; got {old_arns!r}"

    td2 = _task_def(ctx, tok, "sleep 3601")
    updated = ecs.update_service(cluster=tok, service=name, taskDefinition=td2)["service"]
    primary = [d for d in updated["deployments"] if d["status"] == "PRIMARY"]
    assert len(primary) == 1 and primary[0]["taskDefinition"] == td2, (
        f"UpdateService returns one PRIMARY deployment of the new revision; got {updated['deployments']!r}")
    new_dep = primary[0]["id"]
    assert new_dep != old_dep, f"a new task definition starts a new deployment; both are {new_dep!r}"

    prefix = f"(service {name})"
    completed = f"{prefix} (deployment {new_dep}) deployment completed."
    svc = _poll(lambda: _describe(ctx, tok, name),
                lambda s: _settled(s, td2, 1) and completed in {e["message"] for e in s["events"]},
                description="the new deployment COMPLETED alone with 1 RUNNING task")
    dep = svc["deployments"][0]
    got = (dep["id"], dep["status"], dep.get("rolloutStateReason"))
    want = (new_dep, "PRIMARY", f"ECS deployment {new_dep} completed.")
    assert got == want, f"the surviving deployment (id, status, reason): expected {want!r}, got {got!r}"

    new_arns = _tasks(ctx, tok, name, "RUNNING")
    assert len(new_arns) == 1 and new_arns != old_arns, (
        f"one RUNNING replacement task; before {old_arns!r}, after {new_arns!r}")
    new_task = ecs.describe_tasks(cluster=tok, tasks=new_arns)["tasks"][0]
    seen = (new_task.get("startedBy"), new_task["taskDefinitionArn"])
    assert seen == (new_dep, td2), f"the new task (startedBy, revision): expected {(new_dep, td2)!r}, got {seen!r}"

    old = _poll(lambda: ecs.describe_tasks(cluster=tok, tasks=old_arns)["tasks"][0],
                lambda t: t["lastStatus"] == "STOPPED", description="the old task STOPPED")
    seen = (old.get("startedBy"), old.get("stopCode"), old.get("stoppedReason"))
    want = (old_dep, "ServiceSchedulerInitiated", f"Scaling activity initiated by (deployment {old_dep})")
    assert seen == want, f"the old task (startedBy, stopCode, stoppedReason): expected {want!r}, got {seen!r}"

    messages = {e["message"] for e in svc["events"]}
    for want_msg in (f"{prefix} has stopped 1 running tasks: (task {_task_id(old_arns[0])}).",
                     f"{prefix} has started 1 tasks: (task {_task_id(new_arns[0])}).", completed):
        assert want_msg in messages, f"missing event {want_msg!r}; events were {sorted(messages)!r}"


#: A public image Fargate pulls server-side; `sleep` keeps the task RUNNING until it is stopped.
_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"
_TAGS = [{"key": "sim2real:managed", "value": "true"}, {"key": "sim2real:check", "value": CHECK}]
#: A Fargate task is placed, pulled and RUNNING, and a rollout drains its old task, within this.
_ROLLOUT_TIMEOUT_S = 600.0
#: A deleted service drains to INACTIVE, and its tasks stop, before its cluster deletes.
_DRAIN_TIMEOUT_S = 600.0


def _poll(probe, predicate, *, timeout_s=_ROLLOUT_TIMEOUT_S, interval_s=5.0, description="condition"):
    """Poll probe() until predicate(result) holds and return it; raise on the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last: {last!r}")
        time.sleep(interval_s)


def _teardown(fn, what: str, *, gone: tuple, retry: tuple = (), timeout_s=_DRAIN_TIMEOUT_S) -> None:
    """Run a delete: a `gone` code is success, a `retry` code is retried to the deadline and any
    other failure raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone:
                return
            if code not in retry or time.monotonic() >= deadline:
                raise RuntimeError(f"teardown of {what} failed: {code}: {exc}") from exc
        time.sleep(5)


def _cluster(ctx, name: str) -> None:
    """A tagged cluster, deleted once its services and tasks are gone."""
    ecs = ctx.client("ecs")
    ecs.create_cluster(clusterName=name, tags=_TAGS)
    ctx.on_cleanup(lambda: _teardown(
        lambda: ecs.delete_cluster(cluster=name), f"cluster {name}",
        gone=("ClusterNotFoundException",),
        retry=("ClusterContainsServicesException", "ClusterContainsTasksException",
               "UpdateInProgressException")))


def _task_def(ctx, family: str, command: str, stop_timeout: int = 2) -> str:
    """A Fargate awsvpc revision of `family` running `command`; deregistered and deleted."""
    ecs = ctx.client("ecs")
    arn = ecs.register_task_definition(
        family=family, requiresCompatibilities=["FARGATE"], networkMode="awsvpc",
        cpu="256", memory="512", tags=_TAGS,
        containerDefinitions=[{"name": "app", "image": _IMAGE, "essential": True,
                               "command": ["sh", "-c", command], "stopTimeout": stop_timeout}],
    )["taskDefinition"]["taskDefinitionArn"]

    def _drop() -> None:
        status = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]["status"]
        if status == "ACTIVE":
            ecs.deregister_task_definition(taskDefinition=arn)
        if status != "DELETE_IN_PROGRESS":
            ecs.delete_task_definitions(taskDefinitions=[arn])

    ctx.on_cleanup(lambda: _teardown(_drop, f"task definition {arn}", gone=()))
    return arn


def _network(ctx) -> dict:
    """awsvpc settings in the run's own network, with a public IP so the image pulls."""
    net = ctx.network()
    return {"awsvpcConfiguration": {"subnets": list(net.subnet_ids)[:1],
                                    "securityGroups": [net.security_group_id],
                                    "assignPublicIp": "ENABLED"}}


def _delete_service(ctx, cluster: str, name: str) -> None:
    """Force-delete a service and wait until it is INACTIVE and its tasks have stopped."""
    ecs = ctx.client("ecs")
    _teardown(lambda: ecs.delete_service(cluster=cluster, service=name, force=True),
              f"service {name}", gone=("ServiceNotFoundException", "ServiceNotActiveException",
                                       "ClusterNotFoundException"))
    _poll(lambda: ecs.describe_services(cluster=cluster, services=[name])["services"],
          lambda found: all(s["status"] == "INACTIVE" for s in found),
          timeout_s=_DRAIN_TIMEOUT_S, description=f"service {name} INACTIVE")


def _service(ctx, cluster: str, name: str, task_definition: str, desired: int) -> dict:
    """A Fargate service, tagged, with its force-delete registered immediately after."""
    ecs = ctx.client("ecs")
    svc = ecs.create_service(cluster=cluster, serviceName=name, taskDefinition=task_definition,
                             desiredCount=desired, launchType="FARGATE",
                             networkConfiguration=_network(ctx), tags=_TAGS)["service"]
    ctx.on_cleanup(lambda: _delete_service(ctx, cluster, name))
    return svc


def _describe(ctx, cluster: str, name: str) -> dict:
    """The one service `name` in `cluster`, hard-failing on anything else."""
    resp = ctx.client("ecs").describe_services(cluster=cluster, services=[name])
    found = resp["services"]
    assert len(found) == 1, (
        f"DescribeServices must return exactly {name!r}; got "
        f"{[s.get('serviceName') for s in found]!r} with failures {resp.get('failures')!r}")
    return found[0]


def _settled(service: dict, task_definition: str, desired: int) -> bool:
    """One COMPLETED deployment of `task_definition` running `desired` tasks, nothing pending."""
    deps = service["deployments"]
    return (len(deps) == 1 and deps[0]["taskDefinition"] == task_definition
            and deps[0].get("rolloutState") == "COMPLETED"
            and service["runningCount"] == desired and service["pendingCount"] == 0)


def _task_id(task_arn: str) -> str:
    """The id of a task ARN, whose resource is `task/<cluster>/<id>`."""
    resource = task_arn.split(":", 5)[5]
    kind, _cluster_name, task_id = resource.split("/")
    assert kind == "task", f"not a task ARN: {task_arn!r}"
    return task_id


def _tasks(ctx, cluster: str, name: str, desired_status: str) -> list:
    """Every task of service `name` with `desired_status`, paginated."""
    ecs = ctx.client("ecs")
    return [a for page in ecs.get_paginator("list_tasks").paginate(
        cluster=cluster, serviceName=name, desiredStatus=desired_status)
        for a in page["taskArns"]]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
