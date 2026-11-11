"""create-resource-out-of-range-value-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-resource-out-of-range-value-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResource is rejected when a property value falls outside its schema-declared
    range (SQS Queue DelaySeconds max is 900) -- a distinct quota/range boundary from
    invalid-type-name and malformed-desired-state checks."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-behav-queue-")

    # Negative: DelaySeconds=901 exceeds the schema's declared maximum of 900. Cloud
    # Control API accepts the request synchronously and validates asynchronously --
    # the rejection surfaces as a terminal FAILED status with ErrorCode=InvalidRequest.
    bad_state = json.dumps({"QueueName": queue_name, "DelaySeconds": 901})
    bad_resp = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=bad_state)
    bad_final = _wait_for_terminal(cc, bad_resp["ProgressEvent"]["RequestToken"])
    assert bad_final["OperationStatus"] == "FAILED", f"expected FAILED, got {bad_final}"
    assert bad_final.get("ErrorCode") == "InvalidRequest", f"unexpected ErrorCode: {bad_final}"
    # message varies: StatusMessage embeds the downstream SQS Request ID

    # Effect absent: no queue was created under that name.
    absent_code, absent_message = _error(lambda: sqs.get_queue_url(QueueName=queue_name))
    assert absent_code == "AWS.SimpleQueueService.NonExistentQueue", f"unexpected error code: {absent_code}"
    expected_absent_message = "The specified queue does not exist."
    assert absent_message == expected_absent_message, (
        f"expected message {expected_absent_message!r}, got {absent_message!r}"
    )

    # Positive control: the same shape at the boundary value (900, in-range) succeeds.
    good_state = json.dumps(
        {"QueueName": queue_name, "DelaySeconds": 900, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
    )
    resp = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=good_state)
    token = resp["ProgressEvent"]["RequestToken"]
    final = _wait_for_terminal(cc, token)
    assert final["OperationStatus"] == "SUCCESS", f"boundary value 900 should be in-range, got {final}"
    identifier = final["Identifier"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=identifier))
    attrs = sqs.get_queue_attributes(QueueUrl=identifier, AttributeNames=["DelaySeconds"])["Attributes"]
    assert attrs["DelaySeconds"] == "900", f"expected DelaySeconds to round-trip as 900, got {attrs}"


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected SUCCESS raises -- an
    over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
