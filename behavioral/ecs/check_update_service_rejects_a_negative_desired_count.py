"""update-service-rejects-a-negative-desired-count."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-service-rejects-a-negative-desired-count"
GROUP = "service-scaling-rejected"
SERVICES = ["ecs"]

_SLEEP_ONLY = [
    {
        "name": "waiter",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "essential": True,
        "command": ["sh", "-c", "sleep 600"],
    }
]


def _refusal(call):
    """The ``(code, message)`` pair ``call`` is refused with; an acceptance raises instead."""
    try:
        outcome = call()
    except ClientError as exc:
        failure = exc.response["Error"]
        return failure["Code"], failure["Message"]
    raise AssertionError(f"the call was accepted rather than refused, answering {outcome!r}")


def _forget(delete, *gone: str):
    """A teardown that swallows only ``gone`` — the codes meaning the resource is already away."""

    def call() -> None:
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in gone:
                return
            raise

    return call


def _drop_service(ecs, cluster: str, service: str) -> None:
    """Delete the service and hold until it reads INACTIVE, so the cluster can then be deleted."""
    try:
        ecs.delete_service(cluster=cluster, service=service, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("ServiceNotFoundException", "ClusterNotFoundException"):
            return
        raise
    limit = time.monotonic() + 420.0
    while True:
        remains = ecs.describe_services(cluster=cluster, services=[service])["services"]
        if not remains or remains[0]["status"] == "INACTIVE":
            return
        if time.monotonic() > limit:
            raise AssertionError(
                f"service {service!r} reads {remains[0]['status']!r} long after its delete"
            )
        time.sleep(5.0)


def _wanted(ecs, cluster: str, service: str) -> int:
    """What DescribeServices currently reports as the service's desiredCount."""
    return ecs.describe_services(cluster=cluster, services=[service])["services"][0]["desiredCount"]


def _converged(ecs, cluster: str, service: str, target: int, budget_s: float = 90.0) -> None:
    """Hold until DescribeServices reports ``target`` as the desiredCount it accepted."""
    limit = time.monotonic() + budget_s
    while True:
        seen = _wanted(ecs, cluster, service)
        if seen == target:
            return
        if time.monotonic() > limit:
            raise AssertionError(
                f"DescribeServices reports desiredCount {seen!r} after an accepted update to "
                f"{target!r}"
            )
        time.sleep(2.0)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateService refuses a negative desiredCount with one code and message, leaves the count
    the previous accepted update set, and accepts the smallest legal count right after.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_UpdateService.html
    """
    ecs = ctx.client("ecs")
    net = ctx.network()
    label = [{"key": "sim2real", "value": CHECK}]

    cluster = ctx.unique_name("sim2real-behav-ecsneg-cl-")
    ecs.create_cluster(clusterName=cluster, tags=label)
    ctx.on_cleanup(_forget(lambda: ecs.delete_cluster(cluster=cluster), "ClusterNotFoundException"))

    revision = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecsneg-fam-"),
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=_SLEEP_ONLY,
        tags=label,
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(
        _forget(lambda: ecs.deregister_task_definition(taskDefinition=revision), "ClientException")
    )

    service = ctx.unique_name("sim2real-behav-ecsneg-svc-")
    opened = ecs.create_service(
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
        tags=label,
    )["service"]
    ctx.on_cleanup(lambda: _drop_service(ecs, cluster, service))
    assert opened["desiredCount"] == 0, (
        f"the service opened wanting {opened['desiredCount']!r} tasks, expected 0"
    )

    # The positive control: the same operation and the same member, with a count ECS allows.
    ecs.update_service(cluster=cluster, service=service, desiredCount=1)
    _converged(ecs, cluster, service, 1)

    code, message = _refusal(
        lambda: ecs.update_service(cluster=cluster, service=service, desiredCount=-1)
    )
    assert code == "InvalidParameterException", (
        f"a desiredCount of -1 was refused with {code!r} and {message!r}, expected "
        "'InvalidParameterException'"
    )
    expected = "Task count can not be lesser than 0"
    assert message == expected, (
        f"the refusal message was {message!r}, expected {expected!r}"
    )

    # The refusal must change nothing: three consecutive reads still report the accepted count.
    held = [_wanted(ecs, cluster, service) for _ in range(3)]
    assert held == [1, 1, 1], (
        f"after the refused update DescribeServices reported desiredCounts {held!r}, expected the "
        "accepted 1 every time"
    )
    live = ecs.describe_services(cluster=cluster, services=[service])["services"][0]
    assert live["status"] == "ACTIVE", (
        f"the refused update left the service {live['status']!r}, expected 'ACTIVE'"
    )

    # The legal neighbour of -1: zero is accepted on the identical call.
    ecs.update_service(cluster=cluster, service=service, desiredCount=0)
    _converged(ecs, cluster, service, 0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
