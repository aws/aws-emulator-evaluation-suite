"""service-delete-without-force-fails-when-desired-nonzero."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-delete-without-force-fails-when-desired-nonzero"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

DEFAULT_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "amazonlinux:2",
        "cpu": 10,
        "memory": 64,
        "essential": True,
    }
]

def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteService without force=True must reject a service whose desiredCount is still
    non-zero, leave that service untouched, and accept the identical call once desiredCount is
    restored to zero (overly-permissive check)."""
    ecs = ctx.client("ecs")
    cluster = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"),
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["cluster"]
    ctx.on_cleanup(lambda c=cluster: ecs.delete_cluster(cluster=c["clusterName"]))
    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-"),
        containerDefinitions=DEFAULT_CONTAINER_DEFS,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))

    # Positive control: at desiredCount=0, DeleteService without force succeeds outright.
    control_name = ctx.unique_name("sim2real-behav-ecs-svc-control-")
    ecs.create_service(
        cluster=cluster["clusterName"],
        serviceName=control_name,
        taskDefinition=td["taskDefinitionArn"],
        desiredCount=0,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["service"]
    ctx.on_cleanup(
        lambda: ecs.delete_service(cluster=cluster["clusterName"], service=control_name, force=True)
    )
    control_deleted = ecs.delete_service(cluster=cluster["clusterName"], service=control_name)["service"]
    assert control_deleted["status"] in ("INACTIVE", "DRAINING"), (
        f"positive control: delete without force at desiredCount=0 must succeed, "
        f"got status {control_deleted['status']!r}"
    )

    # Break: a service with desiredCount=1.
    svc_name = ctx.unique_name("sim2real-behav-ecs-svc-")
    ecs.create_service(
        cluster=cluster["clusterName"],
        serviceName=svc_name,
        taskDefinition=td["taskDefinitionArn"],
        desiredCount=1,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["service"]
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster["clusterName"], service=svc_name, force=True))

    error = _client_error(lambda: ecs.delete_service(cluster=cluster["clusterName"], service=svc_name))
    code = error.get("Code")
    assert code == "InvalidParameterException", f"unexpected error code: {code!r} ({error!r})"
    assert error.get("Message") == "The service cannot be stopped while it is scaled above 0.", f"unexpected error message: {error!r}"

    # Effect absent: an independent read shows the service untouched by the rejected call.
    still_active = ecs.describe_services(cluster=cluster["clusterName"], services=[svc_name])["services"][0]
    assert still_active["status"] == "ACTIVE", (
        f"service must remain ACTIVE after the rejected delete, got {still_active['status']!r}"
    )
    assert still_active["desiredCount"] == 1, (
        f"desiredCount must be unchanged by the rejected delete, got {still_active['desiredCount']!r}"
    )

    # Restore: drop desiredCount to 0, then the identical delete call now succeeds.
    ecs.update_service(cluster=cluster["clusterName"], service=svc_name, desiredCount=0)
    ecs.delete_service(cluster=cluster["clusterName"], service=svc_name)

    # Terminal read: an independent describe_services call, not the delete call's own response,
    # confirms the service actually left ACTIVE once the delete was no longer refused.
    final_state = ecs.describe_services(cluster=cluster["clusterName"], services=[svc_name])["services"][0]
    assert final_state["status"] in ("INACTIVE", "DRAINING"), (
        f"identical delete call must succeed once desiredCount is restored to 0, "
        f"got status {final_state['status']!r} on independent read"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
