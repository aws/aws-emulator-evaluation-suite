"""namespace-already-exists-error."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "namespace-already-exists-error"
GROUP = 'namespace-lifecycle'
SERVICES = ['servicediscovery']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateHttpNamespace with a Name in use is refused with DuplicateRequest naming the
    original operation and ListNamespaces still lists only the original; once the original is deleted
    (NamespaceNotFound) the identical create succeeds under that name."""

    sd = ctx.client("servicediscovery")

    def _error(fn):
        # An unexpected success raises: accepting what AWS refuses must not read as a code mismatch.
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

    def _namespace_gone(namespace_id):
        # Settling probe: False while the namespace still resolves; any code but NamespaceNotFound raises.
        try:
            sd.get_namespace(Id=namespace_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NamespaceNotFound":
                return True
            raise
        return False

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

    def _create_http_namespace(name):
        resp = sd.create_http_namespace(
            Name=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
        )
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"CreateHttpNamespace failed: {op}")
        return op["Targets"]["NAMESPACE"], resp["OperationId"]

    name = ctx.unique_name("sim2real-behav-sd-ns-dup-")
    namespace_id, create_operation_id = _create_http_namespace(name)
    # Tracks whichever namespace currently owns `name`, since the restore leg below
    # swaps the live namespace id out from under the original create.
    live_id = {"value": namespace_id}
    ctx.on_cleanup(lambda: _delete_namespace(live_id["value"]))

    def create_dup():
        resp = sd.create_http_namespace(Name=name)
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] == "FAIL":
            raise RuntimeError(op.get("ErrorMessage", op.get("ErrorCode", "FAIL")))
        return op

    code, message = _error(create_dup)
    assert code == "DuplicateRequest", f"duplicate namespace name must be rejected as DuplicateRequest, got {code}"
    assert message == (
        f"Another operation of type CreateHttpNamespace and id {create_operation_id} has completed"
    ), f"unexpected DuplicateRequest message: {message!r}"

    # An independent read, not just the mutating call's own error -- confirms the
    # rejected duplicate never actually landed as a second namespace under this name.
    listed = sd.list_namespaces(
        Filters=[{"Name": "NAME", "Values": [name], "Condition": "EQ"}]
    )["Namespaces"]
    assert [n["Id"] for n in listed] == [namespace_id], (
        f"rejected duplicate must leave exactly the original namespace {namespace_id!r} "
        f"visible under {name!r}, got {[n['Id'] for n in listed]!r}"
    )

    # Restore leg: delete the original to free the name (and prove it is actually
    # gone via an independent read before relying on that), then demand the identical
    # create call now succeeds -- distinguishing "this name is permanently rejected"
    # from "this name is rejected only while it is in use".
    _delete_namespace(namespace_id)

    _poll_until(
        lambda: _namespace_gone(namespace_id),
        lambda gone: gone,
        timeout_s=120, interval_s=2.0,
        description=f"GetNamespace({namespace_id}) settling to NamespaceNotFound after delete",
    )

    deadline = time.monotonic() + 60.0
    restored_id = None
    last_code = None
    while time.monotonic() < deadline:
        try:
            restored_id, _ = _create_http_namespace(name)
        except ClientError as exc:
            last_code = exc.response.get("Error", {}).get("Code")
            if last_code not in ("DuplicateRequest", "NamespaceAlreadyExists"):
                raise
            time.sleep(2.0)
            continue
        break
    assert restored_id is not None, (
        f"freeing the name did not make CreateHttpNamespace succeed within 60s "
        f"(last rejection code: {last_code!r})"
    )
    live_id["value"] = restored_id
    # Real AWS can reissue the identical namespace id here, so the id is not asserted
    # either way.

    restored = sd.get_namespace(Id=restored_id)["Namespace"]
    assert restored["Name"] == name, f"restored namespace must be named {name!r}, got {restored['Name']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
