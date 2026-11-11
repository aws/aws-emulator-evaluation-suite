"""service-delete-with-force-succeeds."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "service-delete-with-force-succeeds"
GROUP = 'service-lifecycle'
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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteService with force=True succeeds even when desiredCount is
    non-zero, moving the service out of ACTIVE and, at an independent
    DescribeServices read, all the way to the terminal INACTIVE state."""
    ecs = ctx.client("ecs")
    cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))["cluster"]
    ctx.on_cleanup(lambda c=cluster: ecs.delete_cluster(cluster=c["clusterName"]))
    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-"),
        containerDefinitions=DEFAULT_CONTAINER_DEFS,
    )["taskDefinition"]
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))
    svc_name = ctx.unique_name("sim2real-behav-ecs-svc-")
    svc = ecs.create_service(
        cluster=cluster["clusterName"],
        serviceName=svc_name,
        taskDefinition=td["taskDefinitionArn"],
        desiredCount=1,
    )["service"]
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster["clusterName"], service=svc_name, force=True))

    deleted = ecs.delete_service(
        cluster=cluster["clusterName"], service=svc["serviceName"], force=True
    )["service"]
    assert deleted["status"] in ("DRAINING", "INACTIVE"), (
        f"expected DRAINING/INACTIVE in the DeleteService response, got {deleted['status']}"
    )

    def _describe_status():
        described = ecs.describe_services(cluster=cluster["clusterName"], services=[svc_name])["services"]
        assert described, f"service {svc_name} vanished from DescribeServices after forced delete"
        return described[0]["status"]

    final_status = _poll_until(_describe_status, lambda s: s == "INACTIVE", timeout_s=120.0, interval_s=5.0)
    assert final_status == "INACTIVE", (
        f"expected an independent DescribeServices read to settle on INACTIVE after forced delete, got {final_status}"
    )


def _poll_until(probe, predicate, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
