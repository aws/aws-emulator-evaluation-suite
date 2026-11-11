"""custom-health-status-without-custom-health-config-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-health-status-without-custom-health-config-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["servicediscovery"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateInstanceCustomHealthStatus for a service without HealthCheckCustomConfig is refused with
    ServiceNotFound and GetInstancesHealthStatus answers InstanceNotFound, both with exact messages;
    a service with a custom health check accepts the same call and reads back UNHEALTHY."""
    sd = ctx.client("servicediscovery")
    ns_name = ctx.unique_name("sim2real-behav-ns-")
    namespace_id = _create_http_namespace(ctx, ns_name)

    # Negative: service with no custom health check configured.
    plain_svc_name = ctx.unique_name("sim2real-behav-plainsvc-")
    plain_service_id = _create_service(ctx, namespace_id, plain_svc_name)
    plain_instance_id = ctx.unique_name("sim2real-behav-plaininst-")
    _register_instance(ctx, plain_service_id, plain_instance_id, {"attr": "v"})

    # AWS rejects this with ServiceNotFound regardless of propagation lag -- a service
    # lacking HealthCheckCustomConfig is never indexed by the custom health-check
    # subsystem, so it reports "not found" rather than a config-specific error.
    code, message = _error(
        lambda: sd.update_instance_custom_health_status(
            ServiceId=plain_service_id, InstanceId=plain_instance_id, Status="UNHEALTHY"
        )
    )
    assert code == "ServiceNotFound", f"expected ServiceNotFound, got {code}"
    assert message == (
        f"no service 'arn:aws:servicediscovery:{ctx.region}:{ctx.account}:service/{plain_service_id}'"
    ), f"unexpected ServiceNotFound message: {message!r}"

    # Consistent with the same "not tracked for custom health" reality: reading
    # health status for this instance via the same API family also reports it as not
    # found, rather than returning an UNKNOWN placeholder.
    health_status_code, health_status_message = _error(
        lambda: sd.get_instances_health_status(ServiceId=plain_service_id, Instances=[plain_instance_id])
    )
    assert health_status_code == "InstanceNotFound", f"expected InstanceNotFound, got {health_status_code}"
    assert health_status_message == (
        f"Instance(s) not found for service "
        f"'arn:aws:servicediscovery:{ctx.region}:{ctx.account}:service/{plain_service_id}' "
        f"when trying to retreive: {plain_instance_id}"
    ), (
        f"unexpected InstanceNotFound message: {health_status_message!r}"
    )


    # Positive control: a service *with* HealthCheckCustomConfig accepts the same call.
    healthy_svc_name = ctx.unique_name("sim2real-behav-healthsvc-")
    healthy_service_id = _create_service(
        ctx, namespace_id, healthy_svc_name, HealthCheckCustomConfig={"FailureThreshold": 1}
    )
    healthy_instance_id = ctx.unique_name("sim2real-behav-healthinst-")
    _register_instance(ctx, healthy_service_id, healthy_instance_id, {"attr": "v"})

    _call_with_retry_on_service_not_found(
        lambda: sd.update_instance_custom_health_status(
            ServiceId=healthy_service_id, InstanceId=healthy_instance_id, Status="UNHEALTHY"
        )
    )
    control_status = _poll_health_status(sd, healthy_service_id, healthy_instance_id, expected="UNHEALTHY")
    assert control_status == "UNHEALTHY", (
        f"positive control failed to apply UNHEALTHY status: {control_status}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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


def _poll_health_status(sd, service_id: str, instance_id: str, expected: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> str:
    """Poll GetInstancesHealthStatus, tolerating transient NotFound errors right after
    a create/update, until it reflects `expected` or the timeout elapses."""
    deadline = time.monotonic() + timeout_s
    last: str | None = None
    while time.monotonic() < deadline:
        try:
            status_map = sd.get_instances_health_status(ServiceId=service_id, Instances=[instance_id])["Status"]
            last = status_map.get(instance_id)
            if last == expected:
                return last
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("ServiceNotFound", "InstanceNotFound"):
                raise
        time.sleep(interval_s)
    return last


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
