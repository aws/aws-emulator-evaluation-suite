"""register-instance-missing-required-dns-attribute-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-instance-missing-required-dns-attribute-rejected"
GROUP = "representation"
SERVICES = ["servicediscovery"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterInstance without AWS_INSTANCE_IPV4 in a service whose DnsConfig declares an A record is
    refused with InvalidInput and its exact message and GetInstance answers InstanceNotFound; the same
    InstanceId with the attribute registers and reads back its IPv4 address."""
    vpc_id = _own_vpc_id(ctx)
    sd = ctx.client("servicediscovery")

    ns_name = ctx.unique_name("sim2real-behav-ns-")
    namespace_id = _create_private_dns_namespace(ctx, ns_name, vpc_id)

    svc_name = ctx.unique_name("sim2real-behav-svc-")
    service_id = sd.create_service(
        Name=svc_name,
        NamespaceId=namespace_id,
        DnsConfig={"DnsRecords": [{"Type": "A", "TTL": 60}]},
        Tags=[{"Key": "Name", "Value": svc_name}],
    )["Service"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_service(sd, service_id))

    instance_id = ctx.unique_name("sim2real-behav-inst-")
    error = _client_error(
        lambda: sd.register_instance(ServiceId=service_id, InstanceId=instance_id, Attributes={"custom": "no-ip"})
    )
    assert error.get("Code") == "InvalidInput", f"expected InvalidInput, got {error}"
    assert error.get("Message") == "Required attribute(s) AWS_INSTANCE_IPV4 are missing.", (
        f"unexpected InvalidInput message: {error.get('Message')!r}"
    )

    not_found = _client_error(lambda: sd.get_instance(ServiceId=service_id, InstanceId=instance_id))
    assert not_found.get("Code") == "InstanceNotFound", (
        f"instance should not exist after rejected registration, but GetInstance returned {not_found}"
    )
    assert not_found.get("Message") == instance_id, (
        f"expected InstanceNotFound message {instance_id!r}, got {not_found.get('Message')!r}"
    )

    # Positive control: same InstanceId, same service, with the required attribute.
    _register_instance(ctx, service_id, instance_id, {"AWS_INSTANCE_IPV4": "10.0.0.7"})
    fetched = sd.get_instance(ServiceId=service_id, InstanceId=instance_id)["Instance"]
    assert fetched["Attributes"]["AWS_INSTANCE_IPV4"] == "10.0.0.7", (
        f"expected AWS_INSTANCE_IPV4=10.0.0.7 on the positive-control instance, got {fetched['Attributes']}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises, so an emulator
    accepting input real AWS refuses is not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _wait_operation(ctx, operation_id: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> dict[str, Any]:
    sd = ctx.client("servicediscovery")
    deadline = time.monotonic() + timeout_s
    op: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            return op
        time.sleep(interval_s)
    raise AssertionError(f"operation {operation_id} did not reach a terminal state within {timeout_s}s (last={op})")


def _own_vpc_id(ctx) -> str:
    """The run's shared network VPC, which the private DNS namespace is associated with."""
    return ctx.network().vpc_id


def _create_private_dns_namespace(ctx, name: str, vpc_id: str) -> str:
    sd = ctx.client("servicediscovery")
    op_id = sd.create_private_dns_namespace(Name=name, Vpc=vpc_id, Tags=[{"Key": "Name", "Value": name}])[
        "OperationId"
    ]
    op = _wait_operation(ctx, op_id, timeout_s=300.0, interval_s=5.0)
    assert op["Status"] == "SUCCESS", f"namespace create failed: {op}"
    namespace_id = op["Targets"]["NAMESPACE"]

    def _cleanup():
        try:
            del_op_id = sd.delete_namespace(Id=namespace_id)["OperationId"]
            _wait_operation(ctx, del_op_id, timeout_s=300.0, interval_s=5.0)
        except sd.exceptions.NamespaceNotFound:
            pass

    ctx.on_cleanup(_cleanup)
    return namespace_id


def _safe_delete_service(sd, service_id: str) -> None:
    try:
        sd.delete_service(Id=service_id)
    except sd.exceptions.ServiceNotFound:
        pass


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
