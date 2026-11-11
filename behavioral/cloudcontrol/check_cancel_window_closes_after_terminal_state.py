"""cancel-window-closes-after-terminal-state."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-window-closes-after-terminal-state"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudcontrol"]

_TERMINAL = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelResourceRequest on a request already in SUCCESS fails with ValidationException and
    leaves the request and queue untouched; a cancel that wins the race against a fresh create
    reaches CANCEL_COMPLETE and the queue is gone."""
    cc = ctx.client("cloudcontrol")

    name_a = ctx.unique_name("sim2real-cc-cancelclosed-")
    create_a = cc.create_resource(
        TypeName="AWS::SQS::Queue", DesiredState=json.dumps({"QueueName": name_a})
    )
    token_a = create_a["ProgressEvent"]["RequestToken"]
    final_a = _poll_terminal(cc, token_a, timeout_s=90.0)
    ctx.on_cleanup(lambda: _cleanup_delete(cc, "AWS::SQS::Queue", final_a.get("Identifier")))
    assert final_a["OperationStatus"] == "SUCCESS", f"expected create to reach SUCCESS, got {final_a}"

    code, message = _client_error(lambda: cc.cancel_resource_request(RequestToken=token_a))
    assert code == "ValidationException", (
        f"expected ValidationException canceling a terminal request, got {code!r}"
    )
    expected = f"Request {token_a} is already in status SUCCESS"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    recheck = cc.get_resource_request_status(RequestToken=token_a)["ProgressEvent"]
    assert recheck["OperationStatus"] == "SUCCESS", (
        f"expected rejected cancel to leave status SUCCESS, got {recheck}"
    )

    described = cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=final_a["Identifier"])
    assert described["ResourceDescription"]["Identifier"] == final_a["Identifier"], (
        f"expected the queue to still exist after a rejected cancel, got {described}"
    )

    # Positive control: a cancel issued right after a fresh create, while the window may be open.
    name_b = ctx.unique_name("sim2real-cc-cancelopen-")
    create_b = cc.create_resource(
        TypeName="AWS::SQS::Queue", DesiredState=json.dumps({"QueueName": name_b})
    )
    token_b = create_b["ProgressEvent"]["RequestToken"]

    try:
        cc.cancel_resource_request(RequestToken=token_b)
        cancel_code, cancel_message = None, None
    except ClientError as exc:
        cancel_code, cancel_message = exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    final_b = _poll_terminal(cc, token_b, timeout_s=90.0)
    ctx.on_cleanup(lambda: _cleanup_delete(cc, "AWS::SQS::Queue", final_b.get("Identifier")))

    identifier_b = final_b.get("Identifier") or name_b
    try:
        cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier_b)
        get_code_b, get_message_b = None, None
    except ClientError as exc:
        get_code_b, get_message_b = exc.response["Error"]["Code"], exc.response["Error"]["Message"]

    if cancel_code is None:
        assert final_b["OperationStatus"] == "CANCEL_COMPLETE", (
            f"expected an accepted in-window cancel to reach CANCEL_COMPLETE, got {final_b}"
        )
        assert get_code_b == "ResourceNotFoundException", (
            f"status CANCEL_COMPLETE but GetResource did not 404, got {get_code_b!r}"
        )
        expected_b = _handler_not_found("AWS::SQS::Queue", identifier_b, get_message_b)
        assert get_message_b == expected_b, f"expected message {expected_b!r}, got {get_message_b!r}"
    else:
        # Lost the race: the create was already terminal.
        assert cancel_code == "ValidationException", (
            f"expected ValidationException for a too-late cancel, got {cancel_code!r}"
        )
        expected_late = f"Request {token_b} is already in status SUCCESS"
        assert cancel_message == expected_late, (
            f"expected message {expected_late!r}, got {cancel_message!r}"
        )
        assert final_b["OperationStatus"] == "SUCCESS", (
            f"expected the untouched create to remain SUCCESS, got {final_b}"
        )
        assert get_code_b is None, (
            f"status SUCCESS but GetResource failed with {get_code_b!r}"
        )


def _client_error(fn):
    """The (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _handler_not_found(type_name, identifier, message):
    """The handler's NotFound text; its RequestToken is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return (
        f"{type_name} Handler returned status FAILED: Resource of type '{type_name}' with "
        f"identifier '{identifier}' was not found. (HandlerErrorCode: NotFound, RequestToken: {token})"
    )


def _poll_terminal(cc, token, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request did not reach terminal state within {timeout_s}s; last={last}")


def _cleanup_delete(cc, type_name, identifier) -> None:
    if not identifier:
        return
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        token = resp["ProgressEvent"]["RequestToken"]
        _poll_terminal(cc, token, timeout_s=60.0, interval_s=2.0)
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
