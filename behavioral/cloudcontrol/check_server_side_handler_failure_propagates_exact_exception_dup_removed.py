"""server-side-handler-failure-propagates-exact-exception-dup-removed."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-handler-failure-propagates-exact-exception-dup-removed"
GROUP = "server-side"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResource returns a queue that exists, refuses a well-formed but absent queue identifier with
    ResourceNotFoundException, and refuses an unregistered TypeName with TypeNotFoundException and
    "The type '<name>' cannot be found.": two distinct codes for two distinct broken preconditions."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    queue_name = ctx.unique_name("sim2real-cc-precise2-")
    create = cc.create_resource(
        TypeName="AWS::SQS::Queue", DesiredState=json.dumps({"QueueName": queue_name})
    )
    token = create["ProgressEvent"]["RequestToken"]
    final = _poll_progress(ctx, cc, token)
    assert final["OperationStatus"] == "SUCCESS", f"queue create did not succeed: {final}"
    identifier = final["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(cc, "AWS::SQS::Queue", identifier, teardown))

    # Positive control: the resource genuinely exists -> GetResource succeeds with the real state.
    got = cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)
    assert got["ResourceDescription"]["Identifier"] == identifier, (
        f"expected GetResource to echo the created Identifier {identifier!r}, "
        f"got {got['ResourceDescription']['Identifier']!r}"
    )
    props = json.loads(got["ResourceDescription"]["Properties"])
    assert props["QueueName"] == queue_name, (
        f"expected GetResource's Properties.QueueName to be {queue_name!r}, got {props.get('QueueName')!r}"
    )

    # Break precondition #1: well-formed type, but no resource exists under this identifier.
    missing_identifier = identifier + "-does-not-exist"
    # message varies: the handler embeds its own per-call RequestToken, which the check never sees
    code_missing, _ = _error(
        lambda: cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=missing_identifier)
    )
    assert code_missing == "ResourceNotFoundException", code_missing

    # Break precondition #2: the TypeName itself is not a registered/activated extension at all.
    bogus_type = "AWS::Sim2RealNoSuchService::Definitely12345"
    code_bad_type, bad_type_message = _error(
        lambda: cc.get_resource(TypeName=bogus_type, Identifier=identifier)
    )
    assert code_bad_type == "TypeNotFoundException", code_bad_type
    assert bad_type_message == f"The type '{bogus_type}' cannot be found.", (
        f"the refusal must name the unregistered type, got {bad_type_message!r}"
    )

    # The two broken preconditions are surfaced as two DISTINCT exceptions, not one generic error.
    assert code_missing != code_bad_type, (
        "expected the missing-resource and unregistered-type preconditions to surface distinct "
        f"exception codes, but both surfaced {code_missing!r}"
    )


def _poll_progress(ctx: Any, cc: Any, token: str, timeout_s: float = 120.0, interval_s: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"operation did not reach a terminal state within {timeout_s}s: {last}")


def _error(fn):
    """(code, message) fn() is refused with. An unexpected SUCCESS raises, so a target that
    serves what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


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
