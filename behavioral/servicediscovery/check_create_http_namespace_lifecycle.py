"""create-http-namespace-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-http-namespace-lifecycle"
GROUP = 'namespace-lifecycle'
SERVICES = ['servicediscovery']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateHttpNamespace async op reaches SUCCESS and produces a Namespace that GetNamespace/DeleteNamespace can drive to gone."""

    sd = ctx.client("servicediscovery")

    def _error(fn):
        # An unexpected success raises: accepting what AWS refuses must not read as a code mismatch.
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

    def _tolerate_gone(fn):
        # Teardown: the body may already have deleted the resource.
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NamespaceNotFound", "ServiceNotFound"):
                raise

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
        ctx.on_cleanup(lambda: _tolerate_gone(lambda: _delete_namespace(namespace_id)))
        return namespace_id

    name = ctx.unique_name("sim2real-behav-sd-ns-")
    namespace_id = _create_http_namespace(
        name, Description="fidelity test", Tags=[{"Key": "sim2real-owner", "Value": "fidelity"}]
    )

    got = sd.get_namespace(Id=namespace_id)["Namespace"]
    assert got["Name"] == name, f"expected Name={name!r}, got {got['Name']!r}"
    assert got["Type"] == "HTTP", f"expected Type=HTTP, got {got['Type']!r}"
    assert got["Id"] == namespace_id, f"expected Id={namespace_id!r}, got {got['Id']!r}"

    op = _delete_namespace(namespace_id)
    assert op["Status"] == "SUCCESS", f"expected delete Operation Status=SUCCESS, got {op['Status']!r}"

    code, message = _error(lambda: sd.get_namespace(Id=namespace_id))
    assert code == "NamespaceNotFound", f"expected NamespaceNotFound after delete, got {code}"
    assert message == "", f"unexpected NamespaceNotFound message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
