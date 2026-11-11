"""update-resource-invalid-client-token-format-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-resource-invalid-client-token-format-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResource with a ClientToken outside the documented pattern [-A-Za-z0-9+/=]+ is refused
    synchronously with ValidationException and the exact pattern-constraint message and applies no
    patch, while the same patch with a generated token sets VisibilityTimeout to 123."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()

    queue_name = ctx.unique_name("sim2real-cc-token-")
    create_resp = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps(
            {"QueueName": queue_name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ),
    )
    create_final = _poll_request_status(cc, create_resp["ProgressEvent"]["RequestToken"], timeout_s=150.0)
    assert create_final["OperationStatus"] == "SUCCESS", f"setup failed: {create_final}"
    identifier = create_final["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(cc, "AWS::SQS::Queue", identifier, teardown))

    patch = json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 123}])

    # "not a valid token!!" contains spaces, `!`, and no `=`/`+`/`/` -- none of which
    # are in the documented Pattern `[-A-Za-z0-9+/=]+`, so this is genuinely malformed
    # per the API's own schema, independent of any UUID assumption.
    bad_token = "not a valid token!!"
    code, message = _error(
        lambda: cc.update_resource(
            TypeName="AWS::SQS::Queue",
            Identifier=identifier,
            PatchDocument=patch,
            ClientToken=bad_token,
        )
    )
    assert code == "ValidationException", f"unexpected error code: {code}"
    expected = (
        f"1 validation error detected: Value '{bad_token}' at 'clientToken' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [-A-Za-z0-9+/=]+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    props = json.loads(
        cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)["ResourceDescription"][
            "Properties"
        ]
    )
    assert int(props["VisibilityTimeout"]) != 123, f"patch applied despite bad ClientToken: {props}"

    # positive control: the identical patch with a well-formed (default-generated) token succeeds
    update_resp = cc.update_resource(
        TypeName="AWS::SQS::Queue", Identifier=identifier, PatchDocument=patch
    )
    update_final = _poll_request_status(cc, update_resp["ProgressEvent"]["RequestToken"], timeout_s=150.0)
    assert update_final["OperationStatus"] == "SUCCESS", f"control update failed: {update_final}"

    props_after = json.loads(
        cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)["ResourceDescription"][
            "Properties"
        ]
    )
    assert int(props_after["VisibilityTimeout"]) == 123, f"control patch did not apply: {props_after}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts input AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"malformed ClientToken was accepted; returned {result!r}")


def _poll_request_status(cc: Any, request_token: str, timeout_s: float = 60.0) -> dict:
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if last.get("OperationStatus") in terminal:
            return last
        time.sleep(2.0)
    raise AssertionError(f"request never reached a terminal state: {last}")


#: Seconds every teardown of one run shares: the suite's 900 s cleanup budget less a 120 s margin.
_CLEANUP_S = 780.0


class _Teardown:
    """One deadline for all of a run's teardowns, started when the first of them runs."""

    def __init__(self) -> None:
        self._at = None

    def deadline(self) -> float:
        if self._at is None:
            self._at = time.monotonic() + _CLEANUP_S
        return self._at


def _request_outcome(cc, token: str, teardown) -> dict:
    """Poll GetResourceRequestStatus every 2 s until the request ends; return its ProgressEvent."""
    while True:
        event = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if event["OperationStatus"] not in ("PENDING", "IN_PROGRESS", "CANCEL_IN_PROGRESS"):
            return event
        if time.monotonic() >= teardown.deadline():
            raise AssertionError(
                f"request {token} is still {event['OperationStatus']} at the cleanup deadline"
            )
        time.sleep(2)


def _delete_resource(cc, type_name: str, identifier: str, teardown) -> None:
    """DeleteResource and wait for its outcome; a NotFound answer means the resource is gone.

    ConcurrentOperationException and ResourceConflictException (another request holds the
    resource) are retried every 2 s to the shared cleanup deadline; anything else raises."""
    while True:
        try:
            resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConcurrentOperationException", "ResourceConflictException"):
                raise
            if time.monotonic() >= teardown.deadline():
                raise
            time.sleep(2)
    event = _request_outcome(cc, resp["ProgressEvent"]["RequestToken"], teardown)
    if event["OperationStatus"] == "FAILED" and event.get("ErrorCode") == "NotFound":
        return
    if event["OperationStatus"] != "SUCCESS":
        raise AssertionError(
            f"DeleteResource of {type_name} {identifier} ended {event['OperationStatus']}: {event}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

