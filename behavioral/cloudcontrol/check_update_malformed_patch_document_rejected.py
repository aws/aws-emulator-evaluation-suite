"""update-malformed-patch-document-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-malformed-patch-document-rejected"
GROUP = "e2e"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResource rejects a structurally invalid JSON Patch document (an object instead of an array of
    ops) with ValidationException, the resource's property is left untouched, and a well-formed patch
    on the same resource still succeeds."""
    cc = ctx.client("cloudcontrol")
    queue_name = ctx.unique_name("sim2real-behav-cc-badpatch-")
    resp = cc.create_resource(
        TypeName="AWS::SQS::Queue", DesiredState=json.dumps({"QueueName": queue_name, "VisibilityTimeout": 30})
    )
    event = _wait_for_progress(ctx, resp["ProgressEvent"]["RequestToken"])
    assert event["OperationStatus"] == "SUCCESS", event
    identifier = event["Identifier"]
    ctx.on_cleanup(lambda: _delete_and_wait(ctx, identifier))

    malformed_patch = json.dumps({"op": "replace", "path": "/VisibilityTimeout", "value": 999})
    code, message = _mutate_error(
        ctx,
        lambda: cc.update_resource(
            TypeName="AWS::SQS::Queue", Identifier=identifier, PatchDocument=malformed_patch
        ),
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = "Invalid PatchDocument: A JSONArray text must start with '[' at 1 [character 2 line 1]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    got = cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)
    props = json.loads(got["ResourceDescription"]["Properties"])
    assert props["VisibilityTimeout"] == 30, (
        f"rejected malformed patch leaked into the resource state: "
        f"expected VisibilityTimeout=30, got {props['VisibilityTimeout']}"
    )

    good_patch = json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 55}])
    upd_resp = cc.update_resource(TypeName="AWS::SQS::Queue", Identifier=identifier, PatchDocument=good_patch)
    upd_event = _wait_for_progress(ctx, upd_resp["ProgressEvent"]["RequestToken"])
    assert upd_event["OperationStatus"] == "SUCCESS", upd_event

    got2 = cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)
    props2 = json.loads(got2["ResourceDescription"]["Properties"])
    assert props2["VisibilityTimeout"] == 55, (
        f"positive-control well-formed patch did not take effect: "
        f"expected VisibilityTimeout=55, got {props2['VisibilityTimeout']}"
    )


def _wait_for_progress(ctx, request_token, timeout_s=180.0, interval_s=2.0):
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    event = None
    while time.monotonic() < deadline:
        event = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if event["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return event
        time.sleep(interval_s)
    raise AssertionError(f"operation did not stabilize within {timeout_s}s, last event={event}")


def _mutate_error(ctx, call_fn):
    """Invoke a create/update/delete call and return its refusal as (code, message), whether it
    surfaces synchronously (ClientError) or via an async FAILED progress event (ErrorCode,
    StatusMessage). A call that is not refused raises."""
    try:
        resp = call_fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    event = _wait_for_progress(ctx, resp["ProgressEvent"]["RequestToken"])
    if event["OperationStatus"] == "FAILED":
        return event.get("ErrorCode"), event.get("StatusMessage", "")
    raise AssertionError(f"expected this call to be refused, but it reached {event}")


def _delete_and_wait(ctx, identifier, type_name="AWS::SQS::Queue"):
    cc = ctx.client("cloudcontrol")
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    try:
        _wait_for_progress(ctx, resp["ProgressEvent"]["RequestToken"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RequestTokenNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
