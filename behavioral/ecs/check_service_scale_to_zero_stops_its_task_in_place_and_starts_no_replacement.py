"""service-scale-to-zero-stops-its-task-in-place-and-starts-no-replacement."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-scale-to-zero-stops-its-task-in-place-and-starts-no-replacement"
GROUP = "service-deployment"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Scaling a running service to 0 keeps its one deployment, stops the task under it with ECS's
    exact reason and event, and launches no replacement.
    Reference: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_UpdateService.html
    """
    ecs = ctx.client("ecs")
    tok = ctx.unique_name("sim2real-behav-ecs-")
    _cluster(ctx, tok)
    td = _task_def(ctx, tok, "sleep 3600")
    name = f"{tok}-svc"
    dep_id = _service(ctx, tok, name, td, 1)["deployments"][0]["id"]
    start = time.monotonic()
    _poll(lambda: _describe(ctx, tok, name), lambda s: _settled(s, td, 1),
          description="the deployment COMPLETED with 1 RUNNING task")
    # A slow first start widens the absence window below; capped so the check stays in budget.
    latency = min(_LATENCY_CAP_S, time.monotonic() - start)
    arns = _tasks(ctx, tok, name, "RUNNING")
    assert len(arns) == 1, f"one RUNNING task before scaling in; got {arns!r}"

    ecs.update_service(cluster=tok, service=name, desiredCount=0)
    svc = _poll(lambda: _describe(ctx, tok, name), lambda s: _settled(s, td, 0),
                description="desiredCount 0 with nothing running or pending")
    deps = [(d["id"], d["status"], d["desiredCount"], d["runningCount"]) for d in svc["deployments"]]
    assert deps == [(dep_id, "PRIMARY", 0, 0)], (
        f"a desiredCount-only update keeps the one deployment, now at 0; got {deps!r}")

    task = _poll(lambda: ecs.describe_tasks(cluster=tok, tasks=arns)["tasks"][0],
                 lambda t: t["lastStatus"] == "STOPPED", description="the task STOPPED")
    seen = (task.get("stopCode"), task.get("stoppedReason"))
    want = ("ServiceSchedulerInitiated", f"Scaling activity initiated by (deployment {dep_id})")
    assert seen == want, f"the scaled-in task (stopCode, stoppedReason): expected {want!r}, got {seen!r}"

    stopped = f"(service {name}) has stopped 1 running tasks: (task {_task_id(arns[0])})."
    svc = _poll(lambda: _describe(ctx, tok, name),
                lambda s: stopped in {e["message"] for e in s["events"]},
                timeout_s=120.0, description="the stop event")

    # No replacement over a window sized from how long the first start took.
    launched = _absent_for(
        lambda: [a for a in _tasks(ctx, tok, name, "RUNNING") if a not in arns], latency,
        poll_s=5.0)
    assert launched == [], f"a service at desiredCount 0 launched {launched!r}"
    counts = (svc["desiredCount"], svc["runningCount"], svc["pendingCount"])
    assert counts == (0, 0, 0), f"(desired, running, pending) after scaling in; got {counts!r}"


def _absent_for(observe, latency_s: float, *, factor: float = 3.0, floor_s: float = 10.0,
                poll_s: float = 1.0) -> list:
    """Everything observe() returned over max(floor_s, factor * latency_s) seconds."""
    window = max(floor_s, factor * latency_s)
    deadline = time.monotonic() + window
    seen: list = []
    while True:
        seen.extend(observe())
        if time.monotonic() >= deadline:
            return seen
        time.sleep(poll_s)


#: A public image Fargate pulls server-side; `sleep` keeps the task RUNNING until it is stopped.
_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"
_TAGS = [{"key": "sim2real:managed", "value": "true"}, {"key": "sim2real:check", "value": CHECK}]
#: A Fargate task is placed, pulled and RUNNING, and a rollout drains its old task, within this.
_ROLLOUT_TIMEOUT_S = 600.0
#: The start latency that sizes the no-replacement window is capped at this.
_LATENCY_CAP_S = 60.0
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
