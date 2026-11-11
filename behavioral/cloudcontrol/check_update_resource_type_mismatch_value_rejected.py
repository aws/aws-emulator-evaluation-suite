"""update-resource-type-mismatch-value-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-resource-type-mismatch-value-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResource is rejected when a JSON Patch value's type mismatches the schema (a
    string where DelaySeconds expects an Integer) -- distinct from the immutable-property
    and invalid-json-patch-syntax boundaries."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-behav-queue-")

    create_resp = cc.create_resource(
        TypeName="AWS::SQS::Queue", DesiredState=json.dumps({"QueueName": queue_name, "DelaySeconds": 0})
    )
    create_final = _wait_for_terminal(cc, create_resp["ProgressEvent"]["RequestToken"])
    assert create_final["OperationStatus"] == "SUCCESS", f"queue create did not succeed: {create_final}"
    identifier = create_final["Identifier"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=identifier))

    # Negative: valid JSON Patch syntax, but the replacement value's type (string) mismatches
    # the schema's declared Integer type for DelaySeconds. Cloud Control API performs
    # JSON-schema model validation synchronously before enqueuing the request, rejecting
    # it immediately with ValidationException.
    bad_patch = json.dumps([{"op": "replace", "path": "/DelaySeconds", "value": "not-a-number"}])
    code, message = _error(
        lambda: cc.update_resource(TypeName="AWS::SQS::Queue", Identifier=identifier, PatchDocument=bad_patch)
    )
    assert code == "ValidationException", f"unexpected error code: {code}"
    expected = (
        "Model validation failed (#/DelaySeconds: expected type: Integer, found: String. This may "
        "occur when a numeric value exceeds 32-bit integer max (2147483647). Consider using "
        "'number' type or ensure value fits in integer range.)"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the live queue's DelaySeconds attribute is unchanged.
    attrs = sqs.get_queue_attributes(QueueUrl=identifier, AttributeNames=["DelaySeconds"])["Attributes"]
    assert attrs["DelaySeconds"] == "0", f"expected DelaySeconds unchanged at 0, got {attrs['DelaySeconds']!r}"

    # Positive control: a type-correct patch to the same property succeeds and is reflected
    # on the live resource.
    good_patch = json.dumps([{"op": "replace", "path": "/DelaySeconds", "value": 5}])
    update_resp = cc.update_resource(TypeName="AWS::SQS::Queue", Identifier=identifier, PatchDocument=good_patch)
    update_final = _wait_for_terminal(cc, update_resp["ProgressEvent"]["RequestToken"])
    assert update_final["OperationStatus"] == "SUCCESS", f"type-correct patch did not succeed: {update_final}"
    attrs2 = sqs.get_queue_attributes(QueueUrl=identifier, AttributeNames=["DelaySeconds"])["Attributes"]
    assert attrs2["DelaySeconds"] == "5", f"expected DelaySeconds updated to 5, got {attrs2['DelaySeconds']!r}"


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_terminal(cc, token, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} did not reach a terminal state in {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
