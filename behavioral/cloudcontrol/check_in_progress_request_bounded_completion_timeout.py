"""in-progress-request-bounded-completion-timeout."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "in-progress-request-bounded-completion-timeout"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudcontrol"]

_TERMINAL = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CreateResource request reaches SUCCESS within 90s, and the terminal ProgressEvent keeps
    its TypeName/Operation/RequestToken, carries an Identifier, and is stable on a repeat read."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-cc-bounded-")
    desired_state = json.dumps({
        "QueueName": name,
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    })

    create_resp = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=desired_state)
    event = create_resp["ProgressEvent"]
    token = event["RequestToken"]
    initial_status = event["OperationStatus"]
    assert initial_status in {"PENDING", "IN_PROGRESS", "SUCCESS"}, (
        f"expected an initial PENDING/IN_PROGRESS/SUCCESS status, got {initial_status!r}"
    )
    assert event["TypeName"] == "AWS::SQS::Queue", (
        f"expected TypeName AWS::SQS::Queue on the initial ProgressEvent, got {event['TypeName']!r}"
    )
    assert event["Operation"] == "CREATE", (
        f"expected Operation CREATE on the initial ProgressEvent, got {event['Operation']!r}"
    )

    final = _poll_terminal(cc, token, timeout_s=90.0, interval_s=2.0)
    ctx.on_cleanup(lambda: _cleanup_delete(cc, "AWS::SQS::Queue", final.get("Identifier")))

    assert final["OperationStatus"] == "SUCCESS", final
    assert final["TypeName"] == "AWS::SQS::Queue", (
        f"expected TypeName AWS::SQS::Queue on the terminal ProgressEvent, got {final['TypeName']!r}"
    )
    assert final["Operation"] == "CREATE", (
        f"expected Operation CREATE on the terminal ProgressEvent, got {final['Operation']!r}"
    )
    assert final["RequestToken"] == token, (
        f"expected the terminal ProgressEvent's RequestToken to equal {token!r}, got {final['RequestToken']!r}"
    )
    assert final.get("Identifier"), "expected an Identifier to be assigned once SUCCESS was reached"

    # a second, independent status query for the same token is stable/idempotent
    repeat = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
    assert repeat["OperationStatus"] == "SUCCESS", (
        f"expected a repeated GetResourceRequestStatus to remain SUCCESS, got {repeat['OperationStatus']!r}"
    )
    assert repeat["Identifier"] == final["Identifier"], (
        f"expected a repeated GetResourceRequestStatus to report the same Identifier "
        f"{final['Identifier']!r}, got {repeat['Identifier']!r}"
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
