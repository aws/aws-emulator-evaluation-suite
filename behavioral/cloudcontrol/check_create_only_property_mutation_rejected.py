"""create-only-property-mutation-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-only-property-mutation-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudcontrol"]

_TYPE_NAME = "AWS::SQS::Queue"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResource must reject a PatchDocument that attempts to change a create-only
    property (SQS QueueName) with NotUpdatableException, leave the resource completely
    unchanged, and still allow a legitimate mutable-property update to succeed."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-cc-immutable-")

    resp = cc.create_resource(
        TypeName=_TYPE_NAME,
        DesiredState=json.dumps({"QueueName": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}),
    )
    create_pe = _wait_for_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    assert create_pe["OperationStatus"] == "SUCCESS", f"create did not succeed: {create_pe}"
    identifier = create_pe["Identifier"]
    ctx.on_cleanup(lambda: _cleanup_delete(cc, _TYPE_NAME, identifier))

    # NEGATIVE: attempt to rename the queue via a JSON Patch on the create-only QueueName.
    bad_patch = json.dumps([{"op": "replace", "path": "/QueueName", "value": name + "-renamed"}])
    code, status, message = _error(
        lambda: cc.update_resource(TypeName=_TYPE_NAME, Identifier=identifier, PatchDocument=bad_patch)
    )
    assert code == "NotUpdatableException", (
        f"expected a create-only property mutation to be rejected with NotUpdatableException, got {code}"
    )
    assert status == 400, f"expected HTTP 400 for the create-only mutation, got {status!r}"
    expected_message = "Invalid patch update: createOnlyProperties [/properties/QueueName] cannot be updated"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Effect absent: the queue's name/identity must be untouched by the rejected update.
    get_resp = cc.get_resource(TypeName=_TYPE_NAME, Identifier=identifier)
    props = json.loads(get_resp["ResourceDescription"]["Properties"])
    assert props["QueueName"] == name, (
        f"queue name must remain '{name}' after the rejected update, got {props.get('QueueName')}"
    )

    # POSITIVE CONTROL: a mutable property update against the very same resource succeeds.
    good_resp = cc.update_resource(
        TypeName=_TYPE_NAME,
        Identifier=identifier,
        PatchDocument=json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 77}]),
    )
    good_pe = _wait_for_terminal(cc, good_resp["ProgressEvent"]["RequestToken"])
    assert good_pe["OperationStatus"] == "SUCCESS", f"expected mutable property update to succeed, got {good_pe}"

    get_resp2 = cc.get_resource(TypeName=_TYPE_NAME, Identifier=identifier)
    props2 = json.loads(get_resp2["ResourceDescription"]["Properties"])
    assert int(props2["VisibilityTimeout"]) == 77, (
        f"expected VisibilityTimeout=77 after the control update, got {props2.get('VisibilityTimeout')}"
    )

    # Teardown in the check, then prove the resource is gone.
    del_resp = cc.delete_resource(TypeName=_TYPE_NAME, Identifier=identifier)
    del_pe = _wait_for_terminal(cc, del_resp["ProgressEvent"]["RequestToken"])
    assert del_pe["OperationStatus"] == "SUCCESS", f"expected DeleteResource to succeed, got {del_pe}"
    code, status, message = _error(lambda: cc.get_resource(TypeName=_TYPE_NAME, Identifier=identifier))
    assert code == "ResourceNotFoundException", f"GetResource after delete: expected ResourceNotFoundException, got {code!r}"
    assert status == 400, f"GetResource after delete: expected HTTP 400, got {status!r}"
    message_head, _, request_id = message.partition(", RequestToken: ")
    expected_message = f"{del_pe['TypeName']} Handler returned status FAILED: Resource of type '{del_pe['TypeName']}' with identifier '{identifier}' was not found. (HandlerErrorCode: NotFound"
    assert message_head == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\)", request_id), f"unexpected request id in {message!r}"


_TERMINAL = ("SUCCESS", "FAILED", "CANCEL_COMPLETE")


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


def _error(fn):
    """Call fn(); return the (Code, HTTP status, Message) of its ClientError. An unexpected
    success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        status = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
