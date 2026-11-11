"""server-side-default-property-populated."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-default-property-populated"
GROUP = "server-side"
SERVICES = ["cloudcontrol"]

_TYPE_NAME = "AWS::SQS::Queue"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResource populates omitted VisibilityTimeout/MaximumMessageSize with the defaults SQS
    itself reports for the queue; after DeleteResource, SQS GetQueueUrl and GetResource both
    report the queue as not found."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-cc-default-")

    # Only the required property is supplied; VisibilityTimeout, MaximumMessageSize, etc.
    # are intentionally omitted so the server must fall back to SQS defaults.
    resp = cc.create_resource(
        TypeName=_TYPE_NAME,
        DesiredState=json.dumps({
            "QueueName": name, "Tags": [{"Key": "sim2real", "Value": CHECK}],
        }),
    )
    token = resp["ProgressEvent"]["RequestToken"]
    pe = _wait_for_terminal(cc, token)
    assert pe["OperationStatus"] == "SUCCESS", f"create did not succeed: {pe}"
    identifier = pe["Identifier"]
    ctx.on_cleanup(lambda: _cleanup_delete(cc, _TYPE_NAME, identifier))

    # The defaults come from SQS itself (the identifier is the queue URL), not hardcoded literals.
    queue_url = identifier
    real_attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["VisibilityTimeout", "MaximumMessageSize"]
    )["Attributes"]
    expected_visibility_timeout = int(real_attrs["VisibilityTimeout"])
    expected_max_message_size = int(real_attrs["MaximumMessageSize"])
    assert expected_visibility_timeout > 0, f"SQS itself reports a non-positive VisibilityTimeout default: {real_attrs}"
    assert expected_max_message_size >= 1024, f"SQS itself reports an implausible MaximumMessageSize default: {real_attrs}"

    # Polled briefly to allow for eventual consistency.
    props = _poll_for_props(cc, identifier)

    assert props.get("VisibilityTimeout") is not None, "VisibilityTimeout must be populated with a default, not absent"
    assert int(props["VisibilityTimeout"]) == expected_visibility_timeout, (
        f"CloudControl reports VisibilityTimeout={props['VisibilityTimeout']} but the real "
        f"SQS queue's default is {expected_visibility_timeout}"
    )

    assert props.get("MaximumMessageSize") is not None, "MaximumMessageSize must be populated with a default, not absent"
    assert int(props["MaximumMessageSize"]) == expected_max_message_size, (
        f"CloudControl reports MaximumMessageSize={props['MaximumMessageSize']} but the real "
        f"SQS queue's default is {expected_max_message_size}"
    )

    deleted = cc.delete_resource(TypeName=_TYPE_NAME, Identifier=identifier)
    delete_event = _wait_for_terminal(cc, deleted["ProgressEvent"]["RequestToken"])
    assert delete_event["OperationStatus"] == "SUCCESS", f"delete did not succeed: {delete_event}"

    sqs_code, sqs_message = _error(lambda: sqs.get_queue_url(QueueName=name))
    assert sqs_code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"SQS's own GetQueueUrl raised {sqs_code!r} after DeleteResource, not the specific "
        "not-found code -- the native queue may still exist"
    )
    assert sqs_message == "The specified queue does not exist.", (
        f"expected SQS's not-found message, got {sqs_message!r}"
    )

    cc_code, _ = _error(lambda: cc.get_resource(TypeName=_TYPE_NAME, Identifier=identifier))
    # message varies: the handler embeds its own per-call RequestToken, which the check never sees
    assert cc_code == "ResourceNotFoundException", (
        f"Cloud Control's own GetResource raised {cc_code!r} after DeleteResource, not "
        "ResourceNotFoundException"
    )


_TERMINAL = ("SUCCESS", "FAILED", "CANCEL_COMPLETE")


def _error(fn):
    """The AWS error (code, message) raised by fn(); raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _wait_for_terminal(cc, token, timeout_s=90.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} never reached terminal state (last={last})")


def _cleanup_delete(cc, type_name, identifier):
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        _wait_for_terminal(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=30)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise


def _poll_for_props(cc, identifier, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = {}
    while time.monotonic() < deadline:
        get_resp = cc.get_resource(TypeName=_TYPE_NAME, Identifier=identifier)
        last = json.loads(get_resp["ResourceDescription"]["Properties"])
        if last.get("VisibilityTimeout") is not None and last.get("MaximumMessageSize") is not None:
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
