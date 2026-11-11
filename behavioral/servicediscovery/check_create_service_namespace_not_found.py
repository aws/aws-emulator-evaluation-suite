"""create-service-namespace-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-service-namespace-not-found"
GROUP = 'service-lifecycle'
SERVICES = ['servicediscovery']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateService referencing a non-existent NamespaceId must fail with NamespaceNotFound, while
    the identical call against a real namespace (the positive control) succeeds — so the rejection
    is attributable to the bogus NamespaceId and not to every CreateService call being refused."""

    sd = ctx.client("servicediscovery")

    def _error(fn):
        try:
            result = fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
        raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

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
        return _poll_until(
            lambda: sd.get_operation(OperationId=operation_id)["Operation"],
            lambda op: op.get("Status") in ("SUCCESS", "FAIL"),
            timeout_s=timeout_s, interval_s=interval_s,
        )

    def _delete_namespace(namespace_id):
        resp = sd.delete_namespace(Id=namespace_id)
        return _wait_for_operation(resp["OperationId"])

    def _create_http_namespace(name, **kwargs):
        resp = sd.create_http_namespace(Name=name, **kwargs)
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"CreateHttpNamespace failed: {op}")
        namespace_id = op["Targets"]["NAMESPACE"]
        ctx.on_cleanup(lambda: _delete_namespace(namespace_id))
        return namespace_id

    # Positive control: CreateService against a real namespace must succeed, so the account and
    # credentials are otherwise healthy for this operation.
    namespace_id = _create_http_namespace(ctx.unique_name("sim2real-behav-sd-ns-orphan-"))
    control_service_id = sd.create_service(
        Name=ctx.unique_name("sim2real-behav-sd-svc-control-"), NamespaceId=namespace_id,
    )["Service"]["Id"]
    ctx.on_cleanup(lambda: sd.delete_service(Id=control_service_id))

    bogus_ns = "ns-" + ctx.unique_name("sim2real-behav-bogus").replace("-", "")[:12]
    code, message = _error(
        lambda: sd.create_service(Name=ctx.unique_name("sim2real-behav-sd-svc-orphan-"), NamespaceId=bogus_ns)
    )
    assert code == "NamespaceNotFound", f"expected NamespaceNotFound, got {code}"
    assert message == bogus_ns, f"expected the message to name the missing namespace {bogus_ns!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
