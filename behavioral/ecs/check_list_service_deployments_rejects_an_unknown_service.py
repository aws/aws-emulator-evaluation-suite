"""list-service-deployments-rejects-an-unknown-service."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-service-deployments-rejects-an-unknown-service"
GROUP = "deployment-listing-rejected"
SERVICES = ["ecs"]

_PARKED = [
    {
        "name": "parked",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "essential": True,
        "command": ["sh", "-c", "sleep 300"],
    }
]


def _denial(call):
    """The ``(code, message)`` pair ``call`` is denied with; an acceptance raises instead."""
    try:
        answer = call()
    except ClientError as exc:
        trouble = exc.response["Error"]
        return trouble["Code"], trouble["Message"]
    raise AssertionError(f"the call went through instead of being denied, returning {answer!r}")


def _discard(delete, *vanished: str):
    """A teardown returning only on ``vanished``, the codes that mean the resource is already out."""

    def call() -> None:
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in vanished:
                return
            raise

    return call


def _unwind_service(ecs, cluster: str, service: str) -> None:
    """Delete the service and wait out its drain, so the cluster delete after it is accepted."""
    try:
        ecs.delete_service(cluster=cluster, service=service, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("ServiceNotFoundException", "ClusterNotFoundException"):
            return
        raise
    cutoff = time.monotonic() + 420.0
    while True:
        rest = ecs.describe_services(cluster=cluster, services=[service])["services"]
        if not rest or rest[0]["status"] == "INACTIVE":
            return
        if time.monotonic() > cutoff:
            raise AssertionError(f"service {service!r} stayed {rest[0]['status']!r} after its delete")
        time.sleep(5.0)


def _briefs(ecs, cluster: str, service: str) -> list:
    """Every ServiceDeployment brief ECS lists for the service, across all pages."""
    gathered: list = []
    cursor = None
    while True:
        page = ecs.list_service_deployments(
            cluster=cluster, service=service, **({"nextToken": cursor} if cursor else {})
        )
        gathered.extend(page["serviceDeployments"])
        cursor = page.get("nextToken")
        if not cursor:
            return gathered


def _listed(ecs, cluster: str, service: str, budget_s: float = 180.0) -> list:
    """The service's deployment briefs once ECS has at least one to list."""
    cutoff = time.monotonic() + budget_s
    while True:
        found = _briefs(ecs, cluster, service)
        if found:
            return found
        if time.monotonic() > cutoff:
            raise AssertionError("ListServiceDeployments never listed a deployment for the service")
        time.sleep(5.0)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListServiceDeployments refuses a service name its cluster never held, with one code and
    message, while the same call on a live service in that cluster lists only that service's work.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ListServiceDeployments.html
    """
    ecs = ctx.client("ecs")
    net = ctx.network()
    mark = [{"key": "sim2real", "value": CHECK}]

    cluster = ctx.unique_name("sim2real-behav-ecslsd-cl-")
    ecs.create_cluster(clusterName=cluster, tags=mark)
    ctx.on_cleanup(_discard(lambda: ecs.delete_cluster(cluster=cluster), "ClusterNotFoundException"))

    revision = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecslsd-fam-"),
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=_PARKED,
        tags=mark,
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(
        _discard(lambda: ecs.deregister_task_definition(taskDefinition=revision), "ClientException")
    )

    service = ctx.unique_name("sim2real-behav-ecslsd-svc-")
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
        tags=mark,
    )
    ctx.on_cleanup(lambda: _unwind_service(ecs, cluster, service))

    # The positive control: the identical call, differing only in the service name it carries.
    owned = _listed(ecs, cluster, service)
    strays = [b["serviceArn"] for b in owned if not b["serviceArn"].endswith(f"/{service}")]
    assert not strays, (
        f"ListServiceDeployments returned {len(strays)} brief(s) for another service: {strays!r}"
    )
    off_cluster = [b["clusterArn"] for b in owned if not b["clusterArn"].endswith(f"/{cluster}")]
    assert not off_cluster, (
        f"ListServiceDeployments returned {len(off_cluster)} brief(s) from another cluster: "
        f"{off_cluster!r}"
    )

    ghost = ctx.unique_name("sim2real-behav-ecslsd-ghost-")
    code, message = _denial(lambda: ecs.list_service_deployments(cluster=cluster, service=ghost))
    assert code == "ServiceNotFoundException", (
        f"a service name the cluster never held was answered with {code!r} and {message!r}, "
        "expected 'ServiceNotFoundException'"
    )
    wanted = "Service not found."
    assert message == wanted, f"the refusal message was {message!r}, expected {wanted!r}"

    # The refusal must not disturb the service that does exist.
    still = _briefs(ecs, cluster, service)
    assert len(still) == len(owned), (
        f"the refused call changed the listing from {len(owned)} to {len(still)} brief(s)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
