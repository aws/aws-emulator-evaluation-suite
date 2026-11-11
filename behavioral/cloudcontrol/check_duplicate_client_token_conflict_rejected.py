"""duplicate-client-token-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-client-token-conflict-rejected"
GROUP = "e2e"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reusing a ClientToken for a CreateResource with a different desired state is refused with
    ClientTokenConflictException naming the token and the owning RequestToken; the second queue is
    never created, the first stays readable, and a create with a fresh token succeeds."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    token = ctx.unique_name("sim2reccitok").replace("_", "-")
    queue_name_a = ctx.unique_name("sim2real-cc-tok-a-")
    queue_name_b = ctx.unique_name("sim2real-cc-tok-b-")
    queue_name_c = ctx.unique_name("sim2real-cc-tok-c-")
    tags_prop = [{"Key": "sim2real", "Value": CHECK}]

    create_a = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps({"QueueName": queue_name_a, "Tags": tags_prop}),
        ClientToken=token,
    )
    event_a = _wait_for_progress(cc, create_a["ProgressEvent"]["RequestToken"])
    assert event_a["OperationStatus"] == "SUCCESS", (
        f"expected SUCCESS creating queue A, got {event_a}"
    )
    queue_url_a = event_a["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(cc, "AWS::SQS::Queue", queue_url_a, teardown))

    # Reuse the SAME token for a request describing a DIFFERENT resource.
    code, message = _error(
        lambda: cc.create_resource(
            TypeName="AWS::SQS::Queue",
            DesiredState=json.dumps({"QueueName": queue_name_b, "Tags": tags_prop}),
            ClientToken=token,
        )
    )
    assert code == "ClientTokenConflictException", (
        f"expected ClientTokenConflictException reusing the token for a different "
        f"desired state, got {code!r}"
    )
    request_token_a = create_a["ProgressEvent"]["RequestToken"]
    assert message == (
        f"ClientToken {token} is already associated with an existing operation with "
        f"RequestToken {request_token_a}"
    ), f"the conflict must name the reused ClientToken and the request that owns it, got {message!r}"

    # Effect absent: queue B was never created (its deterministic URL doesn't exist).
    queue_url_b = f"{ctx.client('sqs').meta.endpoint_url}/{account_id}/{queue_name_b}"
    # message varies: the handler embeds its own per-call RequestToken, which the check never sees
    not_found_code, _ = _error(
        lambda: cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=queue_url_b)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the never-created queue B, "
        f"got {not_found_code!r}"
    )

    # Independent read: queue A (the original, non-conflicting request) is real and usable.
    props = _get_properties(cc, "AWS::SQS::Queue", queue_url_a)
    assert props["QueueName"] == queue_name_a, (
        f"expected queue A's QueueName to be {queue_name_a!r}, got {props.get('QueueName')!r}"
    )

    # Positive control: a fresh, non-conflicting CreateResource (new token) still succeeds —
    # the rejection above is specific to the token reuse, not CloudControl refusing every call.
    create_c = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps({"QueueName": queue_name_c, "Tags": tags_prop}),
        ClientToken=ctx.unique_name("sim2reccitok").replace("_", "-"),
    )
    event_c = _wait_for_progress(cc, create_c["ProgressEvent"]["RequestToken"])
    assert event_c["OperationStatus"] == "SUCCESS", (
        f"expected a fresh, non-conflicting CreateResource to still succeed, got {event_c}"
    )
    queue_url_c = event_c["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(cc, "AWS::SQS::Queue", queue_url_c, teardown))


def _wait_for_progress(cc, request_token: str, timeout_s: float = 180.0, interval_s: float = 2.0) -> dict:
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if last.get("OperationStatus") in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {request_token} did not reach a terminal state; last={last}")


def _get_properties(cc, type_name: str, identifier: str) -> dict:
    resp = cc.get_resource(TypeName=type_name, Identifier=identifier)
    return json.loads(resp["ResourceDescription"]["Properties"])


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, so a target
    that accepts a call AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
