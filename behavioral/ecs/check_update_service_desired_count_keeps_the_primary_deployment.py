"""update-service-desired-count-keeps-the-primary-deployment."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-service-desired-count-keeps-the-primary-deployment"
GROUP = "service-deployments"
SERVICES = ["ecs"]

_IDLE_CONTAINER = [
    {
        "name": "idler",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "essential": True,
        "command": ["sh", "-c", "sleep 1200"],
    }
]


def _undo(delete, *gone: str):
    """A teardown that returns only on ``gone``, the resource's own already-deleted codes."""

    def call() -> None:
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in gone:
                return
            raise

    return call


def _retire_service(ecs, cluster: str, service: str) -> None:
    """Delete the service and wait for INACTIVE, so the cluster delete behind it is legal."""
    try:
        ecs.delete_service(cluster=cluster, service=service, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("ServiceNotFoundException", "ClusterNotFoundException"):
            return
        raise
    deadline = time.monotonic() + 420.0
    while True:
        live = ecs.describe_services(cluster=cluster, services=[service])["services"]
        if not live or live[0]["status"] == "INACTIVE":
            return
        if time.monotonic() > deadline:
            raise AssertionError(
                f"service {service!r} is still {live[0]['status']!r} after its delete"
            )
        time.sleep(5.0)


def _settled(ecs, cluster: str, service: str, running: int, budget_s: float):
    """The service once its one deployment has finished rolling out ``running`` tasks."""
    deadline = time.monotonic() + budget_s
    while True:
        seen = ecs.describe_services(cluster=cluster, services=[service])["services"][0]
        rollouts = [d.get("rolloutState") for d in seen["deployments"]]
        if seen["status"] == "ACTIVE" and seen["runningCount"] == running and rollouts == ["COMPLETED"]:
            return seen
        if time.monotonic() > deadline:
            raise AssertionError(
                f"the service never settled at {running} running task(s): status "
                f"{seen['status']!r}, runningCount {seen['runningCount']!r}, rollouts {rollouts!r}"
            )
        time.sleep(5.0)


def _deployment_arns(ecs, cluster: str, service: str) -> set:
    """Every ServiceDeployment ARN ECS holds for the service, across all pages."""
    found: set = set()
    token = None
    while True:
        page = ecs.list_service_deployments(
            cluster=cluster, service=service, **({"nextToken": token} if token else {})
        )
        found.update(brief["serviceDeploymentArn"] for brief in page["serviceDeployments"])
        token = page.get("nextToken")
        if not token:
            return found


def _running_task_arns(ecs, cluster: str, service: str) -> list:
    """Every RUNNING task ARN the service owns, across all pages."""
    arns: list = []
    token = None
    while True:
        page = ecs.list_tasks(
            cluster=cluster,
            serviceName=service,
            desiredStatus="RUNNING",
            **({"nextToken": token} if token else {}),
        )
        arns.extend(page["taskArns"])
        token = page.get("nextToken")
        if not token:
            return arns


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Scaling a service through UpdateService desiredCount keeps its one deployment — same id and
    createdAt, no new ServiceDeployment record — and that id is what started the placed task.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_UpdateService.html
    Reference: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_Task.html
    """
    ecs = ctx.client("ecs")
    net = ctx.network()
    owner = [{"key": "sim2real", "value": CHECK}]

    cluster = ctx.unique_name("sim2real-behav-ecsscale-cl-")
    ecs.create_cluster(clusterName=cluster, tags=owner)
    ctx.on_cleanup(_undo(lambda: ecs.delete_cluster(cluster=cluster), "ClusterNotFoundException"))

    revision = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecsscale-fam-"),
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=_IDLE_CONTAINER,
        tags=owner,
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(
        _undo(lambda: ecs.deregister_task_definition(taskDefinition=revision), "ClientException")
    )

    service = ctx.unique_name("sim2real-behav-ecsscale-svc-")
    ecs.create_service(
        cluster=cluster,
        serviceName=service,
        taskDefinition=revision,
        desiredCount=0,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": net.subnet_ids,
                "securityGroups": [net.security_group_id],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=owner,
    )
    ctx.on_cleanup(lambda: _retire_service(ecs, cluster, service))

    empty = _settled(ecs, cluster, service, 0, 300.0)
    born = empty["deployments"][0]
    assert empty["desiredCount"] == 0, (
        f"the service was created wanting {empty['desiredCount']!r} tasks, expected 0"
    )
    before = _deployment_arns(ecs, cluster, service)

    ecs.update_service(cluster=cluster, service=service, desiredCount=1)

    grown = _settled(ecs, cluster, service, 1, 600.0)
    kept = grown["deployments"][0]
    assert len(grown["deployments"]) == 1, (
        f"scaling left {len(grown['deployments'])} deployments on the service, expected 1"
    )
    assert kept["id"] == born["id"], (
        f"scaling replaced the deployment: the service now reports {kept['id']!r}, "
        f"it reported {born['id']!r} before the scale"
    )
    assert kept["createdAt"] == born["createdAt"], (
        f"the deployment's createdAt moved from {born['createdAt']!r} to {kept['createdAt']!r}, "
        "so it is a different record"
    )
    assert (kept["desiredCount"], kept["runningCount"]) == (1, 1), (
        f"the kept deployment reports desiredCount {kept['desiredCount']!r} and runningCount "
        f"{kept['runningCount']!r}, expected 1 and 1"
    )
    assert grown["desiredCount"] == 1, (
        f"the scaled service wants {grown['desiredCount']!r} tasks, expected 1"
    )
    assert grown["taskDefinition"] == revision, (
        f"scaling moved the service to {grown['taskDefinition']!r}, expected its own revision"
    )

    after = _deployment_arns(ecs, cluster, service)
    assert after == before, (
        f"scaling changed the ServiceDeployment records from {len(before)} to {len(after)}; "
        f"{len(after - before)} appeared and {len(before - after)} vanished"
    )

    placed = _running_task_arns(ecs, cluster, service)
    assert len(placed) == 1, f"the service runs {len(placed)} task(s) at desiredCount 1, expected 1"
    task = ecs.describe_tasks(cluster=cluster, tasks=placed)["tasks"][0]
    assert task["lastStatus"] == "RUNNING", (
        f"the placed task is {task['lastStatus']!r}, expected 'RUNNING'"
    )
    assert task["taskDefinitionArn"] == revision, (
        f"the placed task runs {task['taskDefinitionArn']!r}, not the service's own revision"
    )
    assert task["startedBy"] == kept["id"], (
        f"the placed task was started by {task['startedBy']!r}, not by the service's one "
        f"deployment {kept['id']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
