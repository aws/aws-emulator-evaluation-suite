"""instance-custom-attribute-numeric-precision-round-trip."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "instance-custom-attribute-numeric-precision-round-trip"
GROUP = "representation"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A high-precision numeric string stored as a custom instance attribute survives
    RegisterInstance and comes back identically from GetInstance -- no float
    coercion, exponent normalization, or trailing-digit truncation."""
    sd = ctx.client("servicediscovery")
    ns_name = ctx.unique_name("sim2real-behav-ns-")
    namespace_id = _create_http_namespace(ctx, ns_name)

    svc_name = ctx.unique_name("sim2real-behav-svc-")
    service_id = _create_service(ctx, namespace_id, svc_name)

    instance_id = ctx.unique_name("sim2real-behav-inst-")
    precise_value = "12345678901234567890123456789.123456789012345678901234567890"
    _register_instance(ctx, service_id, instance_id, {"precision-attr": precise_value})

    fetched = sd.get_instance(ServiceId=service_id, InstanceId=instance_id)["Instance"]["Attributes"]
    assert fetched["precision-attr"] == precise_value, (
        f"numeric string coerced/truncated: {fetched['precision-attr']!r} != {precise_value!r}"
    )


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
    op_id = sd.create_http_namespace(Name=name, Tags=[{"Key": "sim2real-behav", "Value": "true"}])["OperationId"]
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
        Name=name, NamespaceId=namespace_id, Tags=[{"Key": "sim2real-behav", "Value": "true"}], **kwargs
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
