"""discover-instances-revision-survives-health-status-change."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "discover-instances-revision-survives-health-status-change"
GROUP = "discover-instances"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DiscoverInstancesRevision is unchanged by a custom health-status flip, and only moves
    once the registered instance set itself changes, such as a deregistration."""

    sd = ctx.client("servicediscovery")

    def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=2.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    def _wait_for_operation(operation_id, timeout_s=60.0, interval_s=1.5):
        op = _poll_until(
            lambda: sd.get_operation(OperationId=operation_id)["Operation"],
            lambda o: o.get("Status") in ("SUCCESS", "FAIL"),
            timeout_s=timeout_s, interval_s=interval_s,
            description=f"operation {operation_id} reaching a terminal state",
        )
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"operation {operation_id} did not succeed: {op}")
        return op

    def _teardown(undo, *not_found: str):
        def run_undo() -> None:
            try:
                undo()
            except ClientError as exc:
                if exc.response["Error"]["Code"] in not_found:
                    return
                raise
        return run_undo

    def _update_health_tolerating_indexing_lag(timeout_s=60.0, interval_s=3.0):
        # A service with HealthCheckCustomConfig set at creation can still answer
        # ServiceNotFound from UpdateInstanceCustomHealthStatus for a short window before the
        # custom health-check subsystem indexes it; retry only on that exact (code, message).
        expected_message = f"no service 'arn:aws:servicediscovery:{ctx.region}:{ctx.account}:service/{service_id}'"
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                sd.update_instance_custom_health_status(
                    ServiceId=service_id, InstanceId=instance_id, Status="UNHEALTHY"
                )
                return
            except ClientError as exc:
                error = exc.response["Error"]
                if (
                    error["Code"] == "ServiceNotFound"
                    and error.get("Message") == expected_message
                    and time.monotonic() < deadline
                ):
                    time.sleep(interval_s)
                    continue
                raise

    ns_name = ctx.unique_name("sim2real-behav-sd-ns-revhealth-")
    create_ns = sd.create_http_namespace(Name=ns_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    namespace_id = _wait_for_operation(create_ns["OperationId"])["Targets"]["NAMESPACE"]
    ctx.on_cleanup(_teardown(
        lambda: _wait_for_operation(sd.delete_namespace(Id=namespace_id)["OperationId"]),
        "NamespaceNotFound",
    ))

    svc_name = ctx.unique_name("sim2real-behav-sd-svc-revhealth-")
    service_id = sd.create_service(
        Name=svc_name, NamespaceId=namespace_id, HealthCheckCustomConfig={"FailureThreshold": 1},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Service"]["Id"]
    ctx.on_cleanup(_teardown(lambda: sd.delete_service(Id=service_id), "ServiceNotFound"))

    instance_id = ctx.unique_name("sim2real-behav-sd-inst-revhealth-")
    register = sd.register_instance(
        ServiceId=service_id, InstanceId=instance_id,
        Attributes={"AWS_INSTANCE_IPV4": "192.0.2.50", "AWS_INIT_HEALTH_STATUS": "HEALTHY"},
    )
    ctx.on_cleanup(_teardown(
        lambda: _wait_for_operation(
            sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)["OperationId"]
        ),
        "InstanceNotFound", "ServiceNotFound",
    ))
    reg_op = _wait_for_operation(register["OperationId"])
    assert reg_op["Status"] == "SUCCESS", (
        f"RegisterInstance ended in {reg_op['Status']!r}: {reg_op.get('ErrorMessage')!r}"
    )

    def health_status():
        try:
            return sd.get_instances_health_status(ServiceId=service_id)["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InstanceNotFound":
                return {}
            raise

    _poll_until(
        health_status, lambda s: s.get(instance_id) == "HEALTHY", timeout_s=90.0, interval_s=3.0,
        description=f"instance {instance_id} settling HEALTHY after registration",
    )

    def revision():
        return sd.discover_instances_revision(
            NamespaceName=ns_name, ServiceName=svc_name
        )["InstancesRevision"]

    rev_before_flip = revision()

    _update_health_tolerating_indexing_lag()

    _poll_until(
        health_status, lambda s: s.get(instance_id) == "UNHEALTHY", timeout_s=90.0, interval_s=3.0,
        description=f"instance {instance_id} settling UNHEALTHY after UpdateInstanceCustomHealthStatus",
    )

    rev_after_flip = revision()
    assert rev_after_flip == rev_before_flip, (
        f"InstancesRevision moved from {rev_before_flip!r} to {rev_after_flip!r} after a custom "
        f"health-status flip that left the registered instance set untouched"
    )

    # Positive control: deregistering the instance does alter the set, so it must move
    # InstancesRevision away from the value the health-status flip left untouched.
    dereg = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)
    _wait_for_operation(dereg["OperationId"])

    rev_after_deregister = _poll_until(
        revision, lambda r: r != rev_after_flip, timeout_s=30.0, interval_s=2.0,
        description="InstancesRevision moving away from its health-status-flip value after a deregistration",
    )
    assert rev_after_deregister != rev_after_flip, (
        f"InstancesRevision stayed at {rev_after_deregister!r} after a deregistration that removed "
        f"the only registered instance"
    )

    sd.delete_service(Id=service_id)
    _wait_for_operation(sd.delete_namespace(Id=namespace_id)["OperationId"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
