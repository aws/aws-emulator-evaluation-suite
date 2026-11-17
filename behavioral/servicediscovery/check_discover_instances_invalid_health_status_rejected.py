"""discover-instances-invalid-health-status-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "discover-instances-invalid-health-status-rejected"
GROUP = "discover-instances"
SERVICES = ["servicediscovery"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DiscoverInstances rejects a HealthStatus value outside its enum with ValidationException,
    while the same call with a valid HealthStatus succeeds."""

    sd = ctx.client("servicediscovery")

    def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.5, description="condition"):
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

    def _error(fn):
        """The (code, message) ``fn`` raises. An unexpected success raises too, naming what came back."""
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
        raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

    ns_name = ctx.unique_name("sim2real-behav-sd-ns-badhealth-")
    create_ns = sd.create_http_namespace(Name=ns_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    namespace_id = _wait_for_operation(create_ns["OperationId"])["Targets"]["NAMESPACE"]
    ctx.on_cleanup(_teardown(
        lambda: _wait_for_operation(sd.delete_namespace(Id=namespace_id)["OperationId"]),
        "NamespaceNotFound",
    ))

    svc_name = ctx.unique_name("sim2real-behav-sd-svc-badhealth-")
    service_id = sd.create_service(
        Name=svc_name, NamespaceId=namespace_id, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["Service"]["Id"]
    ctx.on_cleanup(_teardown(lambda: sd.delete_service(Id=service_id), "ServiceNotFound"))

    code, message = _error(
        lambda: sd.discover_instances(
            NamespaceName=ns_name, ServiceName=svc_name, HealthStatus="BOGUS"
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "1 validation error detected: Value 'BOGUS' at 'healthStatus' failed to satisfy "
        "constraint: Member must satisfy enum value set: "
        "[ALL, UNHEALTHY, HEALTHY_OR_ELSE_ALL, HEALTHY]"
    ), f"unexpected ValidationException message: {message!r}"

    # Positive control: the identical call with a valid HealthStatus against the same
    # namespace/service succeeds, so the rejection above is specific to the bad enum value.
    positive = sd.discover_instances(NamespaceName=ns_name, ServiceName=svc_name, HealthStatus="ALL")
    assert positive["Instances"] == [], f"expected no instances yet, got {positive['Instances']!r}"

    sd.delete_service(Id=service_id)
    _wait_for_operation(sd.delete_namespace(Id=namespace_id)["OperationId"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
