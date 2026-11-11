"""service-ops-on-missing-cluster-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-ops-on-missing-cluster-not-found"
GROUP = 'error-semantics'
SERVICES = ['ecs']

DEFAULT_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "cpu": 64,
        "memory": 128,
        "essential": True,
    }
]


def _error(fn):
    """Return (code, message) of the ClientError *fn* raises; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError("expected a ClientError, call succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateService, DescribeServices, UpdateService and DeleteService on a nonexistent cluster
    return ClusterNotFoundException; on a real cluster the same calls succeed or fail with a
    service-level code, so the rejection is specific to the missing cluster.
    """
    ecs = ctx.client("ecs")
    bogus_cluster = ctx.unique_name("no-such-cluster-")
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-")
    td = ecs.register_task_definition(
        family=family, containerDefinitions=DEFAULT_CONTAINER_DEFS
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td_arn))

    code, message = _error(
        lambda: ecs.create_service(
            cluster=bogus_cluster,
            serviceName=ctx.unique_name("svc-"),
            taskDefinition=td_arn,
            desiredCount=1,
        )
    )
    assert code == "ClusterNotFoundException", f"CreateService: got {code}"
    assert message == "Cluster not found.", f"CreateService: unexpected message {message!r}"

    code, message = _error(
        lambda: ecs.describe_services(cluster=bogus_cluster, services=["nonexistent-svc"])
    )
    assert code == "ClusterNotFoundException", f"DescribeServices: got {code}"
    assert message == "Cluster not found.", f"DescribeServices: unexpected message {message!r}"

    code, message = _error(
        lambda: ecs.update_service(cluster=bogus_cluster, service="nonexistent-svc", desiredCount=2)
    )
    assert code == "ClusterNotFoundException", f"UpdateService: got {code}"
    assert message == "Cluster not found.", f"UpdateService: unexpected message {message!r}"

    code, message = _error(
        lambda: ecs.delete_service(cluster=bogus_cluster, service="nonexistent-svc")
    )
    assert code == "ClusterNotFoundException", f"DeleteService: got {code}"
    assert message == "Cluster not found.", f"DeleteService: unexpected message {message!r}"

    # Positive control: a real cluster must NOT trip ClusterNotFoundException on
    # any of the same four operations, whether they succeed (CreateService) or
    # fail on the service instead of the cluster (UpdateService, DeleteService).
    # Without this, a stub that unconditionally raises ClusterNotFoundException
    # for these four operations — never checking the cluster at all — would pass
    # every assertion above.
    real_cluster = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=real_cluster, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=real_cluster))

    real_service = ctx.unique_name("svc-")
    created = ecs.create_service(
        cluster=real_cluster,
        serviceName=real_service,
        taskDefinition=td_arn,
        desiredCount=0,
    )["service"]
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=real_cluster, service=real_service))
    assert created["clusterArn"].endswith(f"/{real_cluster}"), (
        f"CreateService on real cluster: unexpected clusterArn {created['clusterArn']!r}"
    )

    desc = ecs.describe_services(cluster=real_cluster, services=[real_service])
    assert not desc["failures"], f"DescribeServices on real cluster: unexpected failures {desc['failures']}"
    assert desc["services"][0]["serviceName"] == real_service, (
        f"DescribeServices on real cluster: got {desc['services']}"
    )

    updated = ecs.update_service(cluster=real_cluster, service=real_service, desiredCount=0)
    assert updated["service"]["clusterArn"].endswith(f"/{real_cluster}"), (
        "UpdateService on real cluster: unexpectedly rejected the real cluster"
    )

    code, message = _error(
        lambda: ecs.update_service(cluster=real_cluster, service="nonexistent-svc", desiredCount=2)
    )
    assert code == "ServiceNotFoundException", (
        f"UpdateService on real cluster + missing service: got {code}, expected the "
        "service-level not-found (not ClusterNotFoundException)"
    )
    assert message == "Service not found.", (
        f"UpdateService on real cluster + missing service: unexpected message {message!r}"
    )

    code, message = _error(
        lambda: ecs.delete_service(cluster=real_cluster, service="nonexistent-svc")
    )
    assert code == "ServiceNotFoundException", (
        f"DeleteService on real cluster + missing service: got {code}, expected the "
        "service-level not-found (not ClusterNotFoundException)"
    )
    # AWS returns this ServiceNotFoundException with an empty message.
    assert message == "", (
        f"DeleteService on real cluster + missing service: unexpected message {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
