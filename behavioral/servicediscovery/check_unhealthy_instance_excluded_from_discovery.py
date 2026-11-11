"""unhealthy-instance-excluded-from-discovery."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unhealthy-instance-excluded-from-discovery"
GROUP = "visibility-timeout-ttl"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Marking an instance UNHEALTHY via UpdateInstanceCustomHealthStatus excludes it
    from DiscoverInstances(HealthStatus=HEALTHY) while it still appears in
    ListInstances -- health-gated *discovery* visibility, not deletion."""
    sd = ctx.client("servicediscovery")
    ns_name = ctx.unique_name("sim2real-behav-ns-")
    namespace_id = _create_http_namespace(ctx, ns_name)

    svc_name = ctx.unique_name("sim2real-behav-svc-")
    service_id = _create_service(
        ctx, namespace_id, svc_name, HealthCheckCustomConfig={"FailureThreshold": 1}
    )

    instance_id = ctx.unique_name("sim2real-behav-inst-")
    _register_instance(ctx, service_id, instance_id, {"custom-attr": "v1"})

    # New instances default to HEALTHY; wait until it is discoverable as healthy.
    _poll_until(
        lambda: _discover_ids(sd, ns_name, svc_name, "HEALTHY"),
        lambda ids: instance_id in ids,
        timeout_s=90.0,
        interval_s=3.0,
    )
    listed_before = {i["Id"] for i in sd.list_instances(ServiceId=service_id)["Instances"]}
    assert instance_id in listed_before, f"instance missing from ListInstances before health transition: {listed_before}"

    # Immediately after register, the health-check subsystem can transiently lag the
    # main index and report ServiceNotFound for this brand-new service -- retry past
    # that propagation window rather than failing on it.
    _call_with_retry_on_service_not_found(
        ctx,
        lambda: sd.update_instance_custom_health_status(
            ServiceId=service_id, InstanceId=instance_id, Status="UNHEALTHY"
        ),
    )

    # Per AWS Cloud Map docs, an UNHEALTHY relay is only "confirmed" if no HEALTHY
    # relay arrives within ~30s, so give this a generous bounded poll rather than
    # asserting immediately.
    _poll_until(
        lambda: _discover_ids(sd, ns_name, svc_name, "HEALTHY"),
        lambda ids: instance_id not in ids,
        timeout_s=90.0,
        interval_s=3.0,
    )

    # The instance is still a registered, listable instance -- it was excluded from
    # the health-filtered discovery view, not removed from the service.
    listed_ids = {i["Id"] for i in sd.list_instances(ServiceId=service_id)["Instances"]}
    assert instance_id in listed_ids, f"instance disappeared from ListInstances entirely: {listed_ids}"

    # And it still appears under a broader/unfiltered health view.
    all_ids = _discover_ids(sd, ns_name, svc_name, "ALL")
    assert instance_id in all_ids, f"instance vanished from DiscoverInstances(HealthStatus=ALL): {all_ids}"


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
    op_id = sd.create_http_namespace(Name=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])["OperationId"]
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
    service_id = sd.create_service(
        Name=name, NamespaceId=namespace_id, Tags=[{"Key": "sim2real-check", "Value": CHECK}], **kwargs
    )["Service"]["Id"]

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


def _discover_ids(sd, namespace_name: str, service_name: str, health_status: str) -> set[str]:
    resp = sd.discover_instances(NamespaceName=namespace_name, ServiceName=service_name, HealthStatus=health_status)
    return {inst["InstanceId"] for inst in resp.get("Instances", [])}


def _call_with_retry_on_service_not_found(ctx, fn, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServiceNotFound" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise



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
