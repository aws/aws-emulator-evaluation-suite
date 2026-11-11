"""deregister-instance-visibility-immediate."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "deregister-instance-visibility-immediate"
GROUP = "visibility-timeout-ttl"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Once DeregisterInstance's async operation reports SUCCESS, the instance is
    immediately absent from DiscoverInstances -- no stale-visibility grace window."""
    sd = ctx.client("servicediscovery")
    ns_name = ctx.unique_name("sim2real-behav-ns-")
    namespace_id = _create_http_namespace(ctx, ns_name)

    svc_name = ctx.unique_name("sim2real-behav-svc-")
    service_id = _create_service(ctx, namespace_id, svc_name)

    instance_id = ctx.unique_name("sim2real-behav-inst-")
    _register_instance(ctx, service_id, instance_id, {"custom-attr": "v1"})

    # Wait for the freshly registered instance to become discoverable (registration
    # propagation has no promptness guarantee, so this side is a bounded poll).
    _poll_until(
        lambda: _discover_ids(sd, ns_name, svc_name),
        lambda ids: instance_id in ids,
        timeout_s=90.0,
        interval_s=3.0,
    )

    # Deregister and wait for the async operation to reach a terminal state.
    op_id = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)["OperationId"]
    op = _wait_operation(ctx, op_id)
    assert op["Status"] == "SUCCESS", f"deregister operation failed: {op}"

    # The moment the operation reports SUCCESS, a single immediate DiscoverInstances
    # call (no retry loop) must already exclude the instance -- that is exactly the
    # "no stale-visibility grace window" contract under test.
    ids_after = _discover_ids(sd, ns_name, svc_name)
    assert instance_id not in ids_after, f"instance still visible immediately after deregister SUCCESS: {ids_after}"


def _wait_operation(ctx, operation_id: str, timeout_s: float = 240.0, interval_s: float = 3.0) -> dict[str, Any]:
    sd = ctx.client("servicediscovery")
    deadline = time.monotonic() + timeout_s
    op: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            return op
        time.sleep(interval_s)
    raise AssertionError(f"operation {operation_id} did not reach a terminal state within {timeout_s}s (last={op})")


def _create_http_namespace(ctx, name: str) -> str:
    sd = ctx.client("servicediscovery")
    op_id = sd.create_http_namespace(Name=name)["OperationId"]
    op = _wait_operation(ctx, op_id)
    assert op["Status"] == "SUCCESS", f"namespace create failed: {op}"
    namespace_id = op["Targets"]["NAMESPACE"]

    def _cleanup():
        try:
            del_op_id = sd.delete_namespace(Id=namespace_id)["OperationId"]
            _wait_operation(ctx, del_op_id)
        except sd.exceptions.NamespaceNotFound:
            pass

    ctx.on_cleanup(_cleanup)
    return namespace_id


def _create_service(ctx, namespace_id: str, name: str, **kwargs) -> str:
    sd = ctx.client("servicediscovery")
    service_id = sd.create_service(Name=name, NamespaceId=namespace_id, **kwargs)["Service"]["Id"]

    def _cleanup():
        try:
            sd.delete_service(Id=service_id)
        except sd.exceptions.ServiceNotFound:
            pass

    ctx.on_cleanup(_cleanup)
    return service_id


def _register_instance(ctx, service_id: str, instance_id: str, attributes: dict[str, str]) -> None:
    sd = ctx.client("servicediscovery")
    op_id = sd.register_instance(ServiceId=service_id, InstanceId=instance_id, Attributes=attributes)["OperationId"]
    op = _wait_operation(ctx, op_id)
    assert op["Status"] == "SUCCESS", f"register_instance failed: {op}"

    def _cleanup():
        try:
            dereg_op_id = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)["OperationId"]
            _wait_operation(ctx, dereg_op_id)
        except sd.exceptions.InstanceNotFound:
            pass
        except sd.exceptions.ServiceNotFound:
            pass

    ctx.on_cleanup(_cleanup)


def _discover_ids(sd, namespace_name: str, service_name: str) -> set[str]:
    resp = sd.discover_instances(NamespaceName=namespace_name, ServiceName=service_name, HealthStatus="ALL")
    return {inst["InstanceId"] for inst in resp.get("Instances", [])}


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
