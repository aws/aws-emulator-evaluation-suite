"""list-services-default-page-size-is-ten."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-services-default-page-size-is-ten"
GROUP = "service-listing"
SERVICES = ["ecs"]

_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "cpu": 256,
        "memory": 512,
        "essential": True,
        "command": ["sh", "-c", "sleep 300"],
    }
]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_cluster_retry(ecs, cluster_arn, timeout_s: float = 180.0) -> None:
    """Deleting a cluster races the eventual-consistency window between the services that just
    drained and the cluster's own aggregate counters; retry through it, then raise."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code != "ClusterContainsServicesException" or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListServices with no maxResults caps a page at the documented default of 10 service
    ARNs and advances through nextToken to return an 11th."""
    ecs = ctx.client("ecs")
    net = ctx.network()

    cluster_name = ctx.unique_name("sim2real-behav-ecs-lsd-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_retry(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-behav-ecs-lsd-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=_CONTAINER_DEFS,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td_arn))

    network_configuration = {
        "awsvpcConfiguration": {
            "subnets": net.subnet_ids,
            "securityGroups": [net.security_group_id],
            "assignPublicIp": "ENABLED",
        }
    }

    names = sorted(ctx.unique_name("sim2real-behav-ecs-lsd-svc-") for _ in range(11))
    for name in names:
        ecs.create_service(
            cluster=cluster_arn,
            serviceName=name,
            taskDefinition=td_arn,
            desiredCount=0,
            launchType="FARGATE",
            networkConfiguration=network_configuration,
            tags=[{"key": "sim2real", "value": "true"}],
        )
        ctx.on_cleanup(
            _teardown(
                lambda n=name: ecs.delete_service(cluster=cluster_arn, service=n),
                "ServiceNotFoundException",
            )
        )

    first = ecs.list_services(cluster=cluster_arn)
    first_names = sorted(a.rsplit("/", 1)[-1] for a in first["serviceArns"])
    assert len(first_names) == 10, f"default ListServices page held {len(first_names)} services, expected 10"
    token = first.get("nextToken")
    assert token, "a cluster with 11 services must report a nextToken after the default 10-item page"

    second = ecs.list_services(cluster=cluster_arn, nextToken=token)
    second_names = sorted(a.rsplit("/", 1)[-1] for a in second["serviceArns"])
    assert len(second_names) == 1, f"the continuation page held {len(second_names)} services, expected 1"
    assert not second.get("nextToken"), (
        f"an exhausted listing must carry no further nextToken, got {second.get('nextToken')!r}"
    )

    seen = sorted(first_names + second_names)
    assert seen == names, f"the two default-size pages returned {seen!r}, expected {names!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
