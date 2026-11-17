"""service-first-rollout-completes-with-matching-deployment-and-task-records."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-first-rollout-completes-with-matching-deployment-and-task-records"
GROUP = "service-deployment"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A new service's one deployment completes with ECS's exact reason, counts that match the
    service's, and RUNNING tasks that record that deployment as startedBy and the service as group.
    Reference: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_Deployment.html
    """
    tok = ctx.unique_name("sim2real-behav-ecs-")
    _cluster(ctx, tok)
    td = _task_def(ctx, tok, "sleep 3600")
    name = f"{tok}-svc"
    created = _service(ctx, tok, name, td, 2)
    deps = created["deployments"]
    assert len(deps) == 1 and deps[0]["status"] == "PRIMARY", (
        f"CreateService returns its one PRIMARY deployment; got {deps!r}")
    dep_id = deps[0]["id"]

    svc = _poll(lambda: _describe(ctx, tok, name), lambda s: _settled(s, td, 2),
                description="one COMPLETED deployment running 2 tasks")
    dep = svc["deployments"][0]
    got = {k: dep.get(k) for k in ("id", "status", "rolloutState", "rolloutStateReason",
                                   "desiredCount", "runningCount", "pendingCount",
                                   "launchType", "taskDefinition")}
    want = {"id": dep_id, "status": "PRIMARY", "rolloutState": "COMPLETED",
            "rolloutStateReason": f"ECS deployment {dep_id} completed.",
            "desiredCount": 2, "runningCount": 2, "pendingCount": 0,
            "launchType": "FARGATE", "taskDefinition": td}
    assert got == want, f"the completed deployment record: expected {want!r}, got {got!r}"
    # A retried Fargate launch counts as a failed task, so failedTasks is only a non-negative count.
    failed = dep.get("failedTasks")
    assert isinstance(failed, int) and failed >= 0, f"failedTasks is a task count; got {failed!r}"
    counts = (svc["desiredCount"], svc["runningCount"], svc["pendingCount"])
    assert counts == (2, 2, 0), f"service (desired, running, pending) must match it; got {counts!r}"

    arns = _tasks(ctx, tok, name, "RUNNING")
    assert len(arns) == 2, f"the service must own exactly 2 RUNNING tasks; got {arns!r}"
    tasks = ctx.client("ecs").describe_tasks(cluster=tok, tasks=arns)["tasks"]
    seen = sorted((t["lastStatus"], t.get("startedBy"), t.get("group"), t["taskDefinitionArn"],
                   t.get("launchType")) for t in tasks)
    expected = [("RUNNING", dep_id, f"service:{name}", td, "FARGATE")] * 2
    assert seen == expected, (
        f"each task: (lastStatus, startedBy, group, taskDefinitionArn, launchType) expected "
        f"{expected!r}, got {seen!r}")


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


def _tasks(ctx, cluster: str, name: str, desired_status: str) -> list:
    """Every task of service `name` with `desired_status`, paginated."""
    ecs = ctx.client("ecs")
    return [a for page in ecs.get_paginator("list_tasks").paginate(
        cluster=cluster, serviceName=name, desiredStatus=desired_status)
        for a in page["taskArns"]]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
