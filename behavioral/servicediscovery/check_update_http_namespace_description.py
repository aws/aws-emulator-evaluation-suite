"""update-http-namespace-description."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-http-namespace-description"
GROUP = 'namespace-update'
SERVICES = ['servicediscovery']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateHttpNamespace's async op reaches SUCCESS and the new Description is reflected by
    GetNamespace; after the namespace is deleted, the identical Description mutation fails
    NamespaceNotFound rather than resurrecting it."""

    sd = ctx.client("servicediscovery")

    def _client_error(fn):
        """Call fn(); return its botocore Error dict. An unexpected success raises."""
        try:
            result = fn()
        except ClientError as exc:
            return exc.response.get("Error", {})
        raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")

    def _namespace_or_error(namespace_id):
        """GetNamespace's Namespace on success, its Error dict on a ClientError."""
        try:
            return sd.get_namespace(Id=namespace_id)["Namespace"]
        except ClientError as exc:
            return exc.response.get("Error", {})

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
        resp = sd.create_http_namespace(Name=name, **kwargs)
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"CreateHttpNamespace failed: {op}")
        namespace_id = op["Targets"]["NAMESPACE"]
        ctx.on_cleanup(_tolerating("NamespaceNotFound", lambda: _delete_namespace(namespace_id)))
        return namespace_id

    namespace_id = _create_http_namespace(ctx.unique_name("sim2real-behav-sd-ns-upd-"), Description="original")

    resp = sd.update_http_namespace(
        Id=namespace_id, Namespace={"Description": "updated-description"}
    )
    op = _wait_for_operation(resp["OperationId"])
    assert op["Status"] == "SUCCESS", f"UpdateHttpNamespace operation ended in {op['Status']}: {op.get('ErrorMessage')}"

    got = sd.get_namespace(Id=namespace_id)["Namespace"]
    assert got["Description"] == "updated-description", (
        f"expected updated Description to be reflected, got {got.get('Description')!r}"
    )

    del_op = _delete_namespace(namespace_id)
    assert del_op["Status"] == "SUCCESS", f"delete ended in {del_op['Status']}: {del_op.get('ErrorMessage')}"

    gone = _poll_until(
        lambda: _namespace_or_error(namespace_id),
        lambda r: r.get("Code") == "NamespaceNotFound",
        timeout_s=60, interval_s=2.0,
        description="GetNamespace reporting NamespaceNotFound after delete",
    )
    assert gone.get("Message") == "", f"expected an empty NamespaceNotFound message, got {gone.get('Message')!r}"

    mutate = _client_error(
        lambda: sd.update_http_namespace(Id=namespace_id, Namespace={"Description": "resurrect-me"})
    )
    assert mutate.get("Code") == "NamespaceNotFound", (
        f"UpdateHttpNamespace on a deleted namespace must fail NamespaceNotFound, got {mutate}"
    )
    assert mutate.get("Message") == namespace_id, (
        f"expected NamespaceNotFound message {namespace_id!r}, got {mutate.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
