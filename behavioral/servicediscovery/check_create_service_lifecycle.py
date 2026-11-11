"""create-service-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-service-lifecycle"
GROUP = 'service-lifecycle'
SERVICES = ['servicediscovery']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateService is synchronous and returns a fully-formed Service; DeleteService then removes it (ServiceNotFound after)."""

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

    def _unless_gone(delete, gone_code):
        # Teardown: an already-deleted resource answers its documented not-found code.
        try:
            delete()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != gone_code:
                raise

    def _create_http_namespace(name, **kwargs):
        resp = sd.create_http_namespace(
            Name=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}], **kwargs
        )
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"CreateHttpNamespace failed: {op}")
        namespace_id = op["Targets"]["NAMESPACE"]
        ctx.on_cleanup(lambda: _unless_gone(lambda: _delete_namespace(namespace_id), "NamespaceNotFound"))
        return namespace_id

    def _create_service(name, namespace_id, **kwargs):
        service_id = sd.create_service(
            Name=name, NamespaceId=namespace_id,
            Tags=[{"Key": "sim2real-check", "Value": CHECK}], **kwargs
        )["Service"]["Id"]
        ctx.on_cleanup(lambda: _unless_gone(lambda: sd.delete_service(Id=service_id), "ServiceNotFound"))
        return service_id

    namespace_id = _create_http_namespace(ctx.unique_name("sim2real-behav-sd-ns-svc-"))
    svc_name = ctx.unique_name("sim2real-behav-sd-svc-")
    service_id = _create_service(svc_name, namespace_id, Description="fidelity")

    got = sd.get_service(Id=service_id)["Service"]
    assert got["Name"] == svc_name
    assert got["NamespaceId"] == namespace_id
    assert got["Id"] == service_id
    assert got.get("InstanceCount", 0) == 0

    sd.delete_service(Id=service_id)
    code, message = _error(lambda: sd.get_service(Id=service_id))
    assert code == "ServiceNotFound", f"expected ServiceNotFound after delete, got {code}"
    assert message == "", f"expected GetService's ServiceNotFound to carry an empty message, got {message!r}"

    # the identifier is reusable: the same Name in the same namespace is free again once the
    # deleted service's Id has stopped existing. Real AWS derives the Service Id from
    # Name+NamespaceId rather than minting a fresh random one, so the very same Id comes back.
    reused_service_id = _create_service(svc_name, namespace_id, Description="fidelity-reused")
    reused = sd.get_service(Id=reused_service_id)["Service"]
    assert reused["Name"] == svc_name
    assert reused_service_id == service_id, (
        f"recreating {svc_name!r} in the same namespace after delete should reuse Service Id "
        f"{service_id!r}, got {reused_service_id!r}"
    )

    # DeleteNamespace rejects a namespace with an active service in it, so retire this one first.
    sd.delete_service(Id=reused_service_id)
    _delete_namespace(namespace_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
