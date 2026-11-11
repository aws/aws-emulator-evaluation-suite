"""e2e-service-discovery-full-flow."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-service-discovery-full-flow"
GROUP = "e2e"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An instance registered in a private DNS namespace's service becomes discoverable, drops out of
    healthy discovery once marked UNHEALTHY while staying listed, and is gone after deregistration;
    the deleted service and namespace then answer not found to a read and to a repeat delete."""
    vpc_id = _default_vpc_id(ctx)
    sd = ctx.client("servicediscovery")

    ns_name = ctx.unique_name("sim2real-behav-e2ens-")
    op_id = sd.create_private_dns_namespace(
        Name=ns_name, Vpc=vpc_id, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["OperationId"]
    op = _wait_operation(ctx, op_id, timeout_s=300.0, interval_s=5.0)
    assert op["Status"] == "SUCCESS", f"namespace create failed: {op}"
    namespace_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _delete_namespace(ctx, namespace_id))

    svc_name = ctx.unique_name("sim2real-behav-e2esvc-")
    service = sd.create_service(
        Name=svc_name,
        NamespaceId=namespace_id,
        DnsConfig={"DnsRecords": [{"Type": "A", "TTL": 60}]},
        HealthCheckCustomConfig={"FailureThreshold": 1},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Service"]
    service_id = service["Id"]
    ctx.on_cleanup(lambda: _delete_service(sd, service_id))

    instance_id = ctx.unique_name("sim2real-behav-e2einst-")
    reg_op_id = sd.register_instance(
        ServiceId=service_id, InstanceId=instance_id, Attributes={"AWS_INSTANCE_IPV4": "10.0.0.9"}
    )["OperationId"]
    reg_op = _wait_operation(ctx, reg_op_id)
    assert reg_op["Status"] == "SUCCESS", f"register_instance failed: {reg_op}"

    def _dereg():
        try:
            dereg_op_id = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)["OperationId"]
            _wait_operation(ctx, dereg_op_id)
        except sd.exceptions.InstanceNotFound:
            pass
        except sd.exceptions.ServiceNotFound:
            pass

    ctx.on_cleanup(_dereg)

    # Transition 1: registration -> discoverable-and-healthy.
    _poll_until(
        lambda: _discover_ids(sd, ns_name, svc_name, "HEALTHY"),
        lambda ids: instance_id in ids,
        timeout_s=90.0,
        interval_s=3.0,
    )

    # Transition 2: custom health -> UNHEALTHY -> excluded from healthy discovery.
    # Immediately after registration the health-check subsystem can transiently lag
    # the main index and report ServiceNotFound -- retry past that propagation window.
    _call_with_retry_on_service_not_found(
        lambda: sd.update_instance_custom_health_status(
            ServiceId=service_id, InstanceId=instance_id, Status="UNHEALTHY"
        )
    )
    _poll_until(
        lambda: _discover_ids(sd, ns_name, svc_name, "HEALTHY"),
        lambda ids: instance_id not in ids,
        timeout_s=90.0,
        interval_s=3.0,
    )
    # Still present overall -- unhealthy, not deleted.
    all_ids = _discover_ids(sd, ns_name, svc_name, "ALL")
    assert instance_id in all_ids, f"{instance_id} missing from ALL-health discovery view {all_ids}; unhealthy must stay listed, not vanish"

    # Transition 3: deregister -> gone from every discovery view.
    dereg_op_id = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)["OperationId"]
    dereg_op = _wait_operation(ctx, dereg_op_id)
    assert dereg_op["Status"] == "SUCCESS", f"deregister failed: {dereg_op}"
    all_ids_after_dereg = _discover_ids(sd, ns_name, svc_name, "ALL")
    assert instance_id not in all_ids_after_dereg, f"{instance_id} still visible in ALL-health discovery view {all_ids_after_dereg} after deregister_instance succeeded"

    # Transition 4: teardown -- service then namespace, both must succeed cleanly, and
    # each deletion is proven both by an independent read and by a repeat mutation on
    # the now-dead id, not merely by the mutating call's own operation status.
    sd.delete_service(Id=service_id)
    try:
        sd.get_service(Id=service_id)
        raise AssertionError(f"get_service still returns {service_id} after delete_service succeeded; expected ServiceNotFound")
    except sd.exceptions.ServiceNotFound as exc:
        message = exc.response["Error"].get("Message", "")
        assert message == "", f"expected an empty message, got {message!r}"
    try:
        sd.delete_service(Id=service_id)
        raise AssertionError(f"delete_service on already-deleted {service_id} returned success instead of raising ServiceNotFound")
    except sd.exceptions.ServiceNotFound as exc:
        message = exc.response["Error"].get("Message", "")
        assert message == service_id, f"expected {service_id!r}, got {message!r}"

    del_ns_op_id = sd.delete_namespace(Id=namespace_id)["OperationId"]
    del_ns_op = _wait_operation(ctx, del_ns_op_id, timeout_s=300.0, interval_s=5.0)
    assert del_ns_op["Status"] == "SUCCESS", f"namespace delete failed: {del_ns_op}"
    assert del_ns_op["Type"] == "DELETE_NAMESPACE", f"expected DELETE_NAMESPACE operation type, got {del_ns_op['Type']!r}"
    try:
        sd.get_namespace(Id=namespace_id)
        raise AssertionError(f"get_namespace still returns {namespace_id} after delete_namespace succeeded; expected NamespaceNotFound")
    except sd.exceptions.NamespaceNotFound as exc:
        message = exc.response["Error"].get("Message", "")
        assert message == "", f"expected an empty message, got {message!r}"
    try:
        sd.delete_namespace(Id=namespace_id)
        raise AssertionError(f"delete_namespace on already-deleted {namespace_id} returned success instead of raising NamespaceNotFound")
    except sd.exceptions.NamespaceNotFound as exc:
        message = exc.response["Error"].get("Message", "")
        assert message == namespace_id, f"expected {namespace_id!r}, got {message!r}"


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


def _default_vpc_id(ctx) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    if not vpcs:
        raise AssertionError(
            "no shared network VPC available in this account/region to create a private DNS "
            "namespace for -- would close by creating/selecting any VPC to pass as Vpc"
        )
    return vpcs[0]["VpcId"]


def _discover_ids(sd, namespace_name: str, service_name: str, health_status: str) -> set[str]:
    resp = sd.discover_instances(NamespaceName=namespace_name, ServiceName=service_name, HealthStatus=health_status)
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


def _delete_service(sd, service_id: str) -> None:
    try:
        sd.delete_service(Id=service_id)
    except sd.exceptions.ServiceNotFound:
        pass


def _call_with_retry_on_service_not_found(fn, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServiceNotFound" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _delete_namespace(ctx, namespace_id: str) -> None:
    sd = ctx.client("servicediscovery")
    try:
        del_op_id = sd.delete_namespace(Id=namespace_id)["OperationId"]
        _wait_operation(ctx, del_op_id, timeout_s=300.0, interval_s=5.0)
    except sd.exceptions.NamespaceNotFound:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
