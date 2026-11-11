"""delete-service-nonzero-desired-count-without-force-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-service-nonzero-desired-count-without-force-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteService without force is refused while desiredCount is non-zero, and restoring
    desiredCount to 0 makes the IDENTICAL unforced call succeed -- proving the rejection tracks
    desiredCount specifically, not a target that requires force=True unconditionally."""
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-ds-cluster-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    taskdef_arn = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-ds-taskdef-"),
        networkMode="bridge",
        requiresCompatibilities=["EC2"],
        containerDefinitions=[
            {"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36", "cpu": 64, "memory": 64, "essential": True, "command": ["sleep", "60"]}
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, taskdef_arn))

    service_name = ctx.unique_name("sim2real-ds-svc-")
    ecs.create_service(cluster=cluster_name, serviceName=service_name, taskDefinition=taskdef_arn, desiredCount=1, launchType="EC2")
    ctx.on_cleanup(lambda: _safe_delete_service(ecs, cluster_name, service_name))

    code, message = _error(lambda: ecs.delete_service(cluster=cluster_name, service=service_name))
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException deleting a service with desiredCount=1 and no force flag, got {code!r}"
    )
    assert message == 'The service cannot be stopped while it is scaled above 0.', f"expected the exact unforced-delete message, got {message!r}"

    described = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"]
    assert described and described[0]["status"] == "ACTIVE" and described[0]["desiredCount"] == 1, (
        f"service was mutated despite the rejected DeleteService call: {described}"
    )

    # restore: scale desiredCount back to 0, then the IDENTICAL delete call (still no force)
    # must now succeed. A target that unconditionally requires force=True for DeleteService
    # would pass the rejection above but fail here, which is exactly the gap this leg closes.
    ecs.update_service(cluster=cluster_name, service=service_name, desiredCount=0)
    _poll_until(
        lambda: ecs.describe_services(cluster=cluster_name, services=[service_name])["services"][0],
        lambda s: s["desiredCount"] == 0 and s["runningCount"] == 0,
        timeout_s=60.0,
        interval_s=2.0,
        description="desiredCount/runningCount converge to 0 after UpdateService",
    )

    restored = ecs.delete_service(cluster=cluster_name, service=service_name)["service"]
    assert restored["status"] in ("DRAINING", "INACTIVE"), (
        f"the identical unforced DeleteService call must succeed once desiredCount is restored "
        f"to 0, got status {restored['status']!r}"
    )


# ===== helpers =====

def _error(fn):
    """The captured AWS error code and message. An unexpected SUCCESS raises rather than returning a falsy
    sentinel, so an over-permissive target cannot pass acceptance off as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected DeleteService to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _safe_delete_service(ecs, cluster_name, service_name):
    try:
        ecs.delete_service(cluster=cluster_name, service=service_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
