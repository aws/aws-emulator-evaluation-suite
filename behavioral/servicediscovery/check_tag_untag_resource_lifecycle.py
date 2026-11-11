"""tag-untag-resource-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-untag-resource-lifecycle"
GROUP = 'tagging'
SERVICES = ['servicediscovery']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource form a consistent cycle on a namespace ARN."""

    sd = ctx.client("servicediscovery")

    def _error(fn):
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
        raise AssertionError("expected a ClientError but the call succeeded")

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

    namespace_id = _create_http_namespace(ctx.unique_name("sim2real-behav-sd-ns-tag-"))
    arn = sd.get_namespace(Id=namespace_id)["Namespace"]["Arn"]

    sd.tag_resource(ResourceARN=arn, Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}])
    tags = {t["Key"]: t["Value"] for t in sd.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tags.get("env") == "test", f"expected env=test, got {tags.get('env')!r}"
    assert tags.get("owner") == "fidelity", f"expected owner=fidelity, got {tags.get('owner')!r}"

    sd.untag_resource(ResourceARN=arn, TagKeys=["owner"])
    tags2 = {t["Key"]: t["Value"] for t in sd.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert "owner" not in tags2, "untagged key must not reappear"
    assert tags2.get("env") == "test", "untouched tag must survive partial untag"

    op = _delete_namespace(namespace_id)
    assert op["Status"] == "SUCCESS", f"delete_namespace did not succeed: {op}"

    get_code, get_message = _error(lambda: sd.get_namespace(Id=namespace_id))
    assert get_code == "NamespaceNotFound", f"expected NamespaceNotFound after delete, got {get_code}"
    assert get_message == "", f"expected GetNamespace's NamespaceNotFound to carry an empty message, got {get_message!r}"

    tag_code, tag_message = _error(
        lambda: sd.tag_resource(ResourceARN=arn, Tags=[{"Key": "post-delete", "Value": "x"}])
    )
    assert tag_code == "ResourceNotFoundException", f"expected ResourceNotFoundException on dead ARN, got {tag_code}"
    assert tag_message == "", f"expected TagResource's ResourceNotFoundException to carry an empty message, got {tag_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
