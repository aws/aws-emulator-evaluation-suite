"""custom-health-status-not-configured-error."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-health-status-not-configured-error"
GROUP = 'overly-permissive'
SERVICES = ['servicediscovery']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateInstanceCustomHealthStatus for a service without HealthCheckCustomConfig is refused with
    ServiceNotFound and GetInstancesHealthStatus answers InstanceNotFound, both with exact messages,
    while a service with HealthCheckCustomConfig accepts the call and reads back UNHEALTHY."""

    sd = ctx.client("servicediscovery")

    def _error(fn):
        # An unexpected success raises: accepting what AWS refuses must not read as a code mismatch.
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

    def _call_or_raise_tolerating_propagation_lag(fn, what, timeout_s=60, interval_s=3.0):
        # A freshly-created service (even with HealthCheckCustomConfig set at creation)
        # can answer ServiceNotFound for a short window before the custom health-check
        # subsystem indexes it. Retry only on that specific code, not on any error.
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ServiceNotFound" and time.monotonic() < deadline:
                    time.sleep(interval_s)
                    continue
                raise AssertionError(
                    f"{what} must succeed for a service with HealthCheckCustomConfig, got {code}"
                ) from exc

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    def _wait_for_operation(operation_id, timeout_s=60, interval_s=1.5):
        # Poll GetOperation until it reaches a terminal state (SUCCESS or FAIL).
        return _poll_until(
            lambda: sd.get_operation(OperationId=operation_id)["Operation"],
            lambda op: op.get("Status") in ("SUCCESS", "FAIL"),
            timeout_s=timeout_s, interval_s=interval_s,
        )

    def _delete_namespace(namespace_id, wait=True):
        resp = sd.delete_namespace(Id=namespace_id)
        if wait:
            return _wait_for_operation(resp["OperationId"])
        return resp

    def _create_http_namespace(name, **kwargs):
        resp = sd.create_http_namespace(Name=name, **kwargs)
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"CreateHttpNamespace failed: {op}")
        namespace_id = op["Targets"]["NAMESPACE"]
        ctx.on_cleanup(lambda: _delete_namespace(namespace_id))
        return namespace_id

    def _create_service(name, namespace_id, **kwargs):
        service_id = sd.create_service(Name=name, NamespaceId=namespace_id, **kwargs)["Service"]["Id"]
        ctx.on_cleanup(lambda: sd.delete_service(Id=service_id))
        return service_id

    def _register_instance(service_id, instance_id, attributes, **kwargs):
        resp = sd.register_instance(
            ServiceId=service_id, InstanceId=instance_id, Attributes=attributes, **kwargs
        )

        def _drop_instance(service_id=service_id, instance_id=instance_id):
            try:
                r = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)
                _wait_for_operation(r["OperationId"], timeout_s=30)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("InstanceNotFound", "ServiceNotFound"):
                    raise

        ctx.on_cleanup(_drop_instance)
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"RegisterInstance failed: {op}")
        return op

    namespace_id = _create_http_namespace(ctx.unique_name("sim2real-behav-sd-ns-nohealth-"))

    # Negative: service with no HealthCheckCustomConfig.
    service_id = _create_service(ctx.unique_name("sim2real-behav-sd-svc-nohealth-"), namespace_id)
    instance_id = ctx.unique_name("sim2real-behav-sd-inst-nohealth-")
    _register_instance(service_id, instance_id, {"custom": "value"})

    code, message = _error(
        lambda: sd.update_instance_custom_health_status(
            ServiceId=service_id, InstanceId=instance_id, Status="UNHEALTHY"
        )
    )
    # Real AWS answers ServiceNotFound here: the service is absent from the
    # custom-health-check registry because it was created without HealthCheckCustomConfig.
    assert code == "ServiceNotFound", (
        f"custom health update on a service without HealthCheckCustomConfig must be rejected "
        f"with ServiceNotFound, got {code}"
    )
    assert message == f"no service 'arn:aws:servicediscovery:{ctx.region}:{ctx.account}:service/{service_id}'", (
        f"unexpected ServiceNotFound message: {message!r}"
    )

    # Independent read at the destination, through a different operation than the one that
    # failed: the same instance is also unreadable via GetInstancesHealthStatus, rather than
    # coming back with an UNKNOWN placeholder -- consistent with "never indexed by the custom
    # health-check subsystem" rather than "indexed but currently unhealthy".
    health_code, health_message = _error(
        lambda: sd.get_instances_health_status(ServiceId=service_id, Instances=[instance_id])
    )
    assert health_code == "InstanceNotFound", (
        f"GetInstancesHealthStatus for an instance under a service without "
        f"HealthCheckCustomConfig must report InstanceNotFound, got {health_code}"
    )
    assert health_message == (
        f"Instance(s) not found for service "
        f"'arn:aws:servicediscovery:{ctx.region}:{ctx.account}:service/{service_id}' "
        f"when trying to retreive: {instance_id}"
    ), (
        f"unexpected InstanceNotFound message: {health_message!r}"
    )

    # Positive control: a same-shaped service that DOES carry HealthCheckCustomConfig accepts
    # the identical call, and the transition is visible on an independent read -- proving the
    # rejection above is specific to the missing config, not a blanket failure of this account
    # or credentials.
    healthy_service_id = _create_service(
        ctx.unique_name("sim2real-behav-sd-svc-health-"),
        namespace_id,
        HealthCheckCustomConfig={"FailureThreshold": 1},
    )
    healthy_instance_id = ctx.unique_name("sim2real-behav-sd-inst-health-")
    _register_instance(healthy_service_id, healthy_instance_id, {"custom": "value"})

    _call_or_raise_tolerating_propagation_lag(
        lambda: sd.update_instance_custom_health_status(
            ServiceId=healthy_service_id, InstanceId=healthy_instance_id, Status="UNHEALTHY"
        ),
        "UpdateInstanceCustomHealthStatus",
    )

    def _read_status():
        resp = sd.get_instances_health_status(ServiceId=healthy_service_id, Instances=[healthy_instance_id])
        return resp["Status"].get(healthy_instance_id)

    observed = _poll_until(
        _read_status,
        lambda status: status == "UNHEALTHY",
        timeout_s=60, interval_s=2.0,
        description="positive-control instance health status == UNHEALTHY",
    )
    assert observed == "UNHEALTHY", (
        f"positive control: service WITH HealthCheckCustomConfig must reflect an applied "
        f"UNHEALTHY status on an independent read, got {observed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
