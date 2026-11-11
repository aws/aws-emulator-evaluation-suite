"""delete-namespace-in-use-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-namespace-in-use-conflict"
GROUP = 'overly-permissive'
SERVICES = ['servicediscovery']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteNamespace with a service still in the namespace is refused with ResourceInUse and its exact
    message and leaves the namespace intact; once the service is gone the same call succeeds, and
    GetNamespace and a second delete answer NamespaceNotFound."""

    sd = ctx.client("servicediscovery")
    tag_spec = [{"Key": "sim2real-check", "Value": CHECK}]

    def _error(fn):
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
        raise AssertionError("expected the call to be rejected, but it succeeded")

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
        resp = sd.create_http_namespace(Name=name, Tags=tag_spec, **kwargs)
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"CreateHttpNamespace failed: {op}")
        namespace_id = op["Targets"]["NAMESPACE"]
        ctx.on_cleanup(lambda: _unless_gone(lambda: _delete_namespace(namespace_id), "NamespaceNotFound"))
        return namespace_id

    def _create_service(name, namespace_id, **kwargs):
        service_id = sd.create_service(Name=name, NamespaceId=namespace_id, Tags=tag_spec, **kwargs)["Service"]["Id"]
        ctx.on_cleanup(lambda: _unless_gone(lambda: sd.delete_service(Id=service_id), "ServiceNotFound"))
        return service_id

    ns_name = ctx.unique_name("sim2real-behav-sd-ns-inuse-")
    namespace_id = _create_http_namespace(ns_name)
    svc_name = ctx.unique_name("sim2real-behav-sd-svc-inuse-")
    service_id = _create_service(svc_name, namespace_id)

    code, message = _error(lambda: sd.delete_namespace(Id=namespace_id))
    assert code == "ResourceInUse", f"namespace delete with active service should fail ResourceInUse, got {code}"
    expected = "Namespace has associated services; delete the services before deleting the namespace"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Effect absent: the blocked delete left the namespace fully intact (independent read).
    ns = sd.get_namespace(Id=namespace_id)["Namespace"]
    assert ns["Id"] == namespace_id and ns["Name"] == ns_name, (
        f"namespace mutated despite blocked delete: expected Id={namespace_id!r} Name={ns_name!r}, got {ns!r}"
    )

    sd.delete_service(Id=service_id)
    op = _delete_namespace(namespace_id)
    assert op["Status"] == "SUCCESS", f"namespace delete should succeed once the blocking service is removed, got {op}"

    # Gone and unusable: an independent read 404s, and a further mutation on the dead id also fails.
    not_found_code, not_found_message = _error(lambda: sd.get_namespace(Id=namespace_id))
    assert not_found_code == "NamespaceNotFound", (
        f"namespace still resolvable after successful delete, expected NamespaceNotFound got {not_found_code}"
    )
    assert not_found_message == "", f"expected GetNamespace's NamespaceNotFound to carry an empty message, got {not_found_message!r}"
    redelete_code, redelete_message = _error(lambda: sd.delete_namespace(Id=namespace_id))
    assert redelete_code == "NamespaceNotFound", (
        f"re-deleting an already-deleted namespace should fail NamespaceNotFound, got {redelete_code}"
    )
    assert redelete_message == namespace_id, f"expected the message to name {namespace_id!r}, got {redelete_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
