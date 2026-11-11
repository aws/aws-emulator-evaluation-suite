"""concurrent-cancel-vs-natural-completion-race."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-cancel-vs-natural-completion-race"
GROUP = "concurrency"
SERVICES = ["cloudcontrol"]

_TERMINAL = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Cancelling a create already in SUCCESS never yields CANCEL_COMPLETE and leaves the queue
    intact; an unknown RequestToken raises RequestTokenNotFoundException, and an in-flight cancel
    is accepted."""
    cc = ctx.client("cloudcontrol")
    queue_name = ctx.unique_name("sim2real-cc-cancel-")
    type_name = "AWS::SQS::Queue"

    create_resp = cc.create_resource(
        TypeName=type_name,
        DesiredState=json.dumps(
            {"QueueName": queue_name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ),
    )
    token = create_resp["ProgressEvent"]["RequestToken"]
    final = _poll_request_status(cc, token, timeout_s=90)
    assert final["OperationStatus"] == "SUCCESS", final
    identifier = final["Identifier"]
    ctx.on_cleanup(lambda: _best_effort_delete(cc, type_name, identifier))

    # A late cancel is either rejected with ValidationException or accepted as a no-op echoing
    # the still-terminal status; either way it must not flip the request to CANCEL_COMPLETE.
    try:
        cancel_resp = cc.cancel_resource_request(RequestToken=token)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ValidationException", f"expected ValidationException, got {code}"
        message = exc.response["Error"]["Message"]
        expected = f"Request {token} is already in status SUCCESS"
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        status = cancel_resp["ProgressEvent"]["OperationStatus"]
        assert status != "CANCEL_COMPLETE", (
            f"cancel of an already-SUCCESS request unexpectedly reported CANCEL_COMPLETE: {cancel_resp}"
        )

    described = cc.get_resource(TypeName=type_name, Identifier=identifier)
    assert described["ResourceDescription"]["Identifier"] == identifier, (
        f"expected {identifier}, got {described['ResourceDescription'].get('Identifier')}"
    )

    # Shows the ValidationException above is about terminal state, not a generic bad-token path.
    bogus_token = "bogus-request-token-0000000000000"
    bogus_code, bogus_message = _client_error(
        lambda: cc.cancel_resource_request(RequestToken=bogus_token)
    )
    assert bogus_code == "RequestTokenNotFoundException", bogus_code
    expected_bogus = f"Request with token {bogus_token} was not found"
    assert bogus_message == expected_bogus, (
        f"expected message {expected_bogus!r}, got {bogus_message!r}"
    )

    # Positive control: without it the rejection above could mean every cancel is rejected.
    table_name = ctx.unique_name("sim2real-cc-cancelinflight-")
    table_create = cc.create_resource(
        TypeName="AWS::DynamoDB::Table",
        DesiredState=json.dumps(
            {
                "TableName": table_name,
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                "BillingMode": "PAY_PER_REQUEST",
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            }
        ),
    )
    table_token = table_create["ProgressEvent"]["RequestToken"]
    ctx.on_cleanup(lambda: _best_effort_delete(cc, "AWS::DynamoDB::Table", table_name))

    try:
        cc.cancel_resource_request(RequestToken=table_token)
    except ClientError as exc:
        raise AssertionError(
            f"expected an in-flight cancel to be accepted, got {exc.response['Error']['Code']}"
        ) from exc
    table_final = _poll_request_status(cc, table_token, timeout_s=180)
    assert table_final["OperationStatus"] in ("CANCEL_COMPLETE", "SUCCESS"), table_final


def _poll_request_status(cc, token, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} did not reach terminal state within {timeout_s}s: {last}")


def _client_error(fn):
    """The (code, message) of the ClientError fn() raises; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _best_effort_delete(cc, type_name, identifier):
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        _poll_request_status(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=180)
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
