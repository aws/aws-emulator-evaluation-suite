"""base64-blob-property-round-trip."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "base64-blob-property-round-trip"
GROUP = "representation"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A base64-encoded binary blob stored as an SSM Parameter Value (padding included) round-trips
    byte-for-byte identical through CreateResource/GetResource -- no re-encoding or padding loss."""
    cc = ctx.client("cloudcontrol")
    param_name = ctx.unique_name("sim2real-behav-cc-b64-")
    raw_blob = bytes(range(0, 64)) + b"\x00\x01\xff\xfe\xfd\x99"
    encoded = base64.b64encode(raw_blob).decode("ascii")
    assert encoded.endswith("="), "fixture blob should exercise base64 padding"

    desired_state = json.dumps(
        {"Name": param_name, "Type": "String", "Value": encoded, "Tags": {"sim2real": CHECK}}
    )
    resp = cc.create_resource(TypeName="AWS::SSM::Parameter", DesiredState=desired_state)
    event = _wait_for_progress(ctx, resp["ProgressEvent"]["RequestToken"])
    assert event["OperationStatus"] == "SUCCESS", event
    identifier = event["Identifier"]
    ctx.on_cleanup(lambda: _delete_and_wait(ctx, identifier))

    got = cc.get_resource(TypeName="AWS::SSM::Parameter", Identifier=identifier)
    props = json.loads(got["ResourceDescription"]["Properties"])
    assert props["Value"] == encoded, props["Value"]
    decoded = base64.b64decode(props["Value"])
    assert decoded == raw_blob, f"decoded Value bytes {decoded!r} differ from what was written {raw_blob!r}"

    _delete_and_wait(ctx, identifier)
    code, message = _client_error(lambda: cc.get_resource(TypeName="AWS::SSM::Parameter", Identifier=identifier))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code}"
    expected = _handler_not_found("AWS::SSM::Parameter", identifier, message)
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """The (code, message) of the ClientError fn() raises; raises if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("expected the call to raise a ClientError, it succeeded")


def _handler_not_found(type_name, identifier, message):
    """The handler's NotFound text; its RequestToken is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return (
        f"{type_name} Handler returned status FAILED: Resource of type '{type_name}' with "
        f"identifier '{identifier}' was not found. (HandlerErrorCode: NotFound, RequestToken: {token})"
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


def _delete_and_wait(ctx, identifier, type_name="AWS::SSM::Parameter"):
    cc = ctx.client("cloudcontrol")
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    final = _wait_for_progress(ctx, resp["ProgressEvent"]["RequestToken"])
    if final["OperationStatus"] != "SUCCESS" and final.get("ErrorCode") != "NotFound":
        raise AssertionError(f"deleting {identifier} ended {final['OperationStatus']}: {final}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
