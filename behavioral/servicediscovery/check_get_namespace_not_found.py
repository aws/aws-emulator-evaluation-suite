"""get-namespace-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-namespace-not-found"
GROUP = 'namespace-lifecycle'
SERVICES = ['servicediscovery']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetNamespace on a well-formed but never-created Id must return NamespaceNotFound,
    while the identical call against a real namespace still succeeds -- otherwise a target
    that rejects every GetNamespace would score the same as one that classifies correctly."""

    sd = ctx.client("servicediscovery")

    def _error(fn):
        # An unexpected success raises: accepting what AWS refuses must not read as a code mismatch.
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

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

    def _create_http_namespace(name, **kwargs):
        resp = sd.create_http_namespace(Name=name, **kwargs)
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"CreateHttpNamespace failed: {op}")
        namespace_id = op["Targets"]["NAMESPACE"]
        ctx.on_cleanup(lambda: sd.delete_namespace(Id=namespace_id))
        return namespace_id

    # Positive control: a real namespace must still resolve via GetNamespace, so the
    # not-found result below is proof of classification, not of a target that refuses
    # every GetNamespace call.
    real_name = ctx.unique_name("sim2real-behav-sd-ns-realctrl-")
    real_id = _create_http_namespace(real_name)
    got = sd.get_namespace(Id=real_id)["Namespace"]
    assert got["Id"] == real_id, f"expected Id {real_id!r}, got {got.get('Id')!r}"
    assert got["Name"] == real_name, f"expected Name {real_name!r}, got {got.get('Name')!r}"

    bogus_id = "ns-" + ctx.unique_name("sim2real-behav-bogus").replace("-", "")[:12]
    code, message = _error(lambda: sd.get_namespace(Id=bogus_id))
    assert code == "NamespaceNotFound", f"expected NamespaceNotFound, got {code}"
    assert message == "", f"unexpected NamespaceNotFound message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
