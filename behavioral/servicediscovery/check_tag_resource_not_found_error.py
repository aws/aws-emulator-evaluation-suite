"""tag-resource-not-found-error."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-not-found-error"
GROUP = 'tagging'
SERVICES = ['servicediscovery']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After a namespace is deleted (GetNamespace answers NamespaceNotFound), TagResource and
    ListTagsForResource on its ARN both answer ResourceNotFoundException with an empty message."""

    sd = ctx.client("servicediscovery")

    def _error(fn):
        """Call fn(); return the botocore Error.Code and Message if a ClientError is raised. An
        unexpected SUCCESS raises, because a target accepting a call real AWS rejects is the strongest
        signal available."""
        try:
            result = fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
        raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

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
        resp = sd.create_http_namespace(Name=name, **kwargs)
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"CreateHttpNamespace failed: {op}")
        namespace_id = op["Targets"]["NAMESPACE"]
        ctx.on_cleanup(lambda: _unless_gone(lambda: _delete_namespace(namespace_id), "NamespaceNotFound"))
        return namespace_id

    namespace_id = _create_http_namespace(ctx.unique_name("sim2real-behav-sd-ns-tagmissing-"))
    arn = sd.get_namespace(Id=namespace_id)["Namespace"]["Arn"]

    op = _delete_namespace(namespace_id)
    assert op["Status"] == "SUCCESS", f"delete_namespace did not succeed: {op}"

    # Confirm it is really gone before probing TagResource semantics on the dead ARN.
    gone_code, gone_message = _error(lambda: sd.get_namespace(Id=namespace_id))
    assert gone_code == "NamespaceNotFound", f"expected NamespaceNotFound, got {gone_code!r}"
    assert gone_message == "", f"expected GetNamespace's NamespaceNotFound to carry an empty message, got {gone_message!r}"

    code, message = _error(
        lambda: sd.tag_resource(ResourceARN=arn, Tags=[{"Key": "k", "Value": "v"}])
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "", f"expected TagResource's ResourceNotFoundException to carry an empty message, got {message!r}"

    # Effect absent, via an independent operation: no tags were created against the dead ARN either.
    list_code, list_message = _error(lambda: sd.list_tags_for_resource(ResourceARN=arn))
    assert list_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {list_code!r}"
    assert list_message == "", (
        f"expected ListTagsForResource's ResourceNotFoundException to carry an empty message, got {list_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
