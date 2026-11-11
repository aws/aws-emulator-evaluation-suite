"""service-attributes-delete-unknown-key-idempotent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-attributes-delete-unknown-key-idempotent"
GROUP = 'service-attributes'
SERVICES = ['servicediscovery']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteServiceAttributes on a key that was never set is IDEMPOTENT on real AWS -- it must NOT error.

    Empirically real AWS accepts the delete of an absent attribute key and leaves existing
    attributes untouched. An emulator that raises InvalidInput here is over-strict."""

    sd = ctx.client("servicediscovery")

    def _client_error(fn):
        """Call fn(); return its botocore Error dict. An unexpected success raises."""
        try:
            result = fn()
        except ClientError as exc:
            return exc.response.get("Error", {})
        raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")

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

    def _tolerating(not_found_code, fn):
        """Teardown for a resource the check may already have deleted."""
        def _run():
            try:
                fn()
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != not_found_code:
                    raise
        return _run

    def _delete_namespace(namespace_id, wait=True):
        resp = sd.delete_namespace(Id=namespace_id)
        if wait:
            return _wait_for_operation(resp["OperationId"])
        return resp

    def _create_http_namespace(name, **kwargs):
        resp = sd.create_http_namespace(
            Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
        )
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"CreateHttpNamespace failed: {op}")
        namespace_id = op["Targets"]["NAMESPACE"]
        ctx.on_cleanup(_tolerating("NamespaceNotFound", lambda: _delete_namespace(namespace_id)))
        return namespace_id

    def _create_service(name, namespace_id, **kwargs):
        service_id = sd.create_service(
            Name=name, NamespaceId=namespace_id, Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
        )["Service"]["Id"]
        ctx.on_cleanup(_tolerating("ServiceNotFound", lambda: sd.delete_service(Id=service_id)))
        return service_id

    namespace_id = _create_http_namespace(ctx.unique_name("sim2real-behav-sd-ns-attrbad-"))
    service_id = _create_service(ctx.unique_name("sim2real-behav-sd-svc-attrbad-"), namespace_id)

    sd.update_service_attributes(ServiceId=service_id, Attributes={"keep": "yes"})

    # Deleting an absent attribute key must be idempotent: a ClientError here fails the check.
    sd.delete_service_attributes(ServiceId=service_id, Attributes=["never-set-key"])

    got = sd.get_service_attributes(ServiceId=service_id)["ServiceAttributes"]
    assert got["Attributes"].get("keep") == "yes", "no-op delete must not disturb existing attributes"

    sd.delete_service(Id=service_id)
    error = _client_error(lambda: sd.get_service(Id=service_id))
    assert error.get("Code") == "ServiceNotFound", f"deleted service must be gone, got {error}"
    assert error.get("Message") == "", f"expected an empty ServiceNotFound message, got {error.get('Message')!r}"

    _delete_namespace(namespace_id)
    error = _client_error(lambda: sd.get_namespace(Id=namespace_id))
    assert error.get("Code") == "NamespaceNotFound", f"deleted namespace must be gone, got {error}"
    assert error.get("Message") == "", f"expected an empty NamespaceNotFound message, got {error.get('Message')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
