"""custom-health-status-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "custom-health-status-transition"
GROUP = 'custom-health-status'
SERVICES = ['servicediscovery']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateInstanceCustomHealthStatus drives an instance's reported HealthStatus, observable via GetInstancesHealthStatus."""

    sd = ctx.client("servicediscovery")

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

    def _deregister_instance(service_id, instance_id, wait=True):
        resp = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)
        if wait:
            return _wait_for_operation(resp["OperationId"])
        return resp

    namespace_id = _create_http_namespace(ctx.unique_name("sim2real-behav-sd-ns-health-"))
    service_id = _create_service(
        ctx.unique_name("sim2real-behav-sd-svc-health-"),
        namespace_id,
        HealthCheckCustomConfig={"FailureThreshold": 1},
    )
    instance_id = ctx.unique_name("sim2real-behav-sd-inst-health-")
    _register_instance(
        service_id, instance_id, {"custom": "1", "AWS_INIT_HEALTH_STATUS": "HEALTHY"}
    )

    def health_status():
        # GetInstancesHealthStatus can transiently raise InstanceNotFound until the
        # custom health-check record for the new instance is materialized.
        try:
            return sd.get_instances_health_status(ServiceId=service_id)["Status"]
        except Exception as exc:  # noqa: BLE001
            if "InstanceNotFound" in type(exc).__name__ or "InstanceNotFound" in str(exc):
                return {}
            raise

    _poll_until(
        health_status, lambda s: s.get(instance_id) == "HEALTHY", timeout_s=90, interval_s=3,
        description=f"instance {instance_id} reaches HEALTHY after RegisterInstance(AWS_INIT_HEALTH_STATUS=HEALTHY)",
    )

    sd.update_instance_custom_health_status(
        ServiceId=service_id, InstanceId=instance_id, Status="UNHEALTHY"
    )

    final = _poll_until(
        health_status, lambda s: s.get(instance_id) == "UNHEALTHY", timeout_s=90, interval_s=3,
        description=f"instance {instance_id} reaches UNHEALTHY after UpdateInstanceCustomHealthStatus(Status=UNHEALTHY)",
    )
    assert final[instance_id] == "UNHEALTHY", (
        f"GetInstancesHealthStatus must report UNHEALTHY for {instance_id} after "
        f"UpdateInstanceCustomHealthStatus(Status=UNHEALTHY), got {final.get(instance_id)!r}"
    )

    _deregister_instance(service_id, instance_id)
    sd.delete_service(Id=service_id)
    _delete_namespace(namespace_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
