"""service-attributes-unicode-value-round-trip."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "service-attributes-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A service attribute value containing multi-byte unicode (CJK + emoji) written
    via UpdateServiceAttributes is returned byte-for-byte unchanged by
    GetServiceAttributes."""
    sd = ctx.client("servicediscovery")
    ns_name = ctx.unique_name("sim2real-behav-ns-")
    namespace_id = _create_http_namespace(ctx, ns_name)

    svc_name = ctx.unique_name("sim2real-behav-svc-")
    service_id = _create_service(ctx, namespace_id, svc_name)

    unicode_value = "\u65e5\u672c\u8a9e-\U0001f680-caf\u00e9-\u00df\u00fc\u00f1"  # 日本語-🚀-café-ßüñ
    sd.update_service_attributes(ServiceId=service_id, Attributes={"unicode-attr": unicode_value})

    fetched = sd.get_service_attributes(ServiceId=service_id)["ServiceAttributes"]["Attributes"]
    assert fetched["unicode-attr"] == unicode_value, f"unicode value mangled: {fetched['unicode-attr']!r} != {unicode_value!r}"


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
    op_id = sd.create_http_namespace(Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}])["OperationId"]
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
        Name=name, NamespaceId=namespace_id, Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )["Service"]["Id"]

    def _cleanup():
        try:
            sd.delete_service(Id=service_id)
        except sd.exceptions.ServiceNotFound:
            pass

    ctx.on_cleanup(_cleanup)
    return service_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
