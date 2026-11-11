"""e2e-immutable-property-update-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-immutable-property-update-rejected"
GROUP = "e2e"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResource patching a createOnly property is rejected with NotUpdatableException and
    leaves the resource untouched, while an update to a mutable property on it succeeds."""
    cc = ctx.client("cloudcontrol")
    type_name = "AWS::SQS::Queue"
    queue_name = ctx.unique_name("sim2real-behav-cc-immut-")

    desired_state = json.dumps({"QueueName": queue_name, "VisibilityTimeout": 30})
    create_event = _wait_terminal(
        cc, cc.create_resource(TypeName=type_name, DesiredState=desired_state)["ProgressEvent"]
    )
    assert create_event["OperationStatus"] == "SUCCESS", create_event
    identifier = create_event["Identifier"]
    ctx.on_cleanup(lambda: _delete_if_present(cc, type_name, identifier))

    # Break exactly one thing: FifoQueue is a createOnly property on AWS::SQS::Queue,
    # so flipping it on an already-created standard queue must be rejected.
    bad_patch = json.dumps([{"op": "add", "path": "/FifoQueue", "value": True}])
    code, message = _expect_rejected(
        cc, lambda: cc.update_resource(TypeName=type_name, Identifier=identifier, PatchDocument=bad_patch)
    )
    assert code == "NotUpdatableException", f"expected NotUpdatableException, got {code!r}"
    assert message == (
        "Invalid patch update: createOnlyProperties [/properties/FifoQueue] cannot be updated"
    ), f"the refusal must name the createOnly property, got {message!r}"

    # Effect absent: the resource's properties are unchanged by the rejected update.
    got = cc.get_resource(TypeName=type_name, Identifier=identifier)
    props = json.loads(got["ResourceDescription"]["Properties"])
    assert not props.get("FifoQueue", False), f"rejected FifoQueue flip leaked into resource state: {props}"
    assert int(props["VisibilityTimeout"]) == 30, f"expected VisibilityTimeout=30 unchanged, got {props}"

    # Positive control, same file: a legitimate update to a mutable property on
    # the same resource still succeeds -- proving the rejection above is specific
    # to the immutable field, not a backend that rejects every UpdateResource call.
    good_patch = json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 45}])
    update_event = _wait_terminal(
        cc,
        cc.update_resource(TypeName=type_name, Identifier=identifier, PatchDocument=good_patch)[
            "ProgressEvent"
        ],
    )
    assert update_event["OperationStatus"] == "SUCCESS", update_event

    got = cc.get_resource(TypeName=type_name, Identifier=identifier)
    props = json.loads(got["ResourceDescription"]["Properties"])
    assert int(props["VisibilityTimeout"]) == 45, f"positive-control update did not take effect: {props}"


def _expect_rejected(cc, fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return the terminal (code, message), whether it surfaces synchronously
    (ClientError) or via an async FAILED progress event (ErrorCode, StatusMessage). An unexpected
    success raises: accepting an update AWS refuses is a distinct failure from a wrong code."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    event = _wait_terminal(cc, resp["ProgressEvent"])
    if event["OperationStatus"] == "FAILED":
        return event.get("ErrorCode"), event.get("StatusMessage")
    raise AssertionError(f"expected UpdateResource to be rejected, but it SUCCEEDED: {event}")


def _wait_terminal(cc, progress_event: dict, timeout_s: float = 120.0, interval_s: float = 2.0) -> dict:
    status = progress_event["OperationStatus"]
    token = progress_event["RequestToken"]
    deadline = time.monotonic() + timeout_s
    while status in ("PENDING", "IN_PROGRESS"):
        if time.monotonic() > deadline:
            raise AssertionError(
                f"request {token} did not reach a terminal state within {timeout_s}s, "
                f"last event={progress_event}"
            )
        time.sleep(interval_s)
        progress_event = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        status = progress_event["OperationStatus"]
    return progress_event


def _delete_if_present(cc, type_name: str, identifier: str) -> None:
    """Delete and wait; an already-gone resource is fine, any other outcome raises."""
    try:
        cc.get_resource(TypeName=type_name, Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    final = _wait_terminal(cc, cc.delete_resource(TypeName=type_name, Identifier=identifier)["ProgressEvent"])
    if final["OperationStatus"] != "SUCCESS" and final.get("ErrorCode") != "NotFound":
        raise AssertionError(f"deleting {identifier} ended {final['OperationStatus']}: {final}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
