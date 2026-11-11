"""list-resource-requests-chronological-order."""
from __future__ import annotations

import json
import re
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-resource-requests-chronological-order"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]

_TERMINAL = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
_TYPE_NAME = "AWS::SSM::Parameter"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResourceRequests entries for one parameter, ordered by EventTime, are CREATE, UPDATE,
    DELETE with the RequestTokens of the requests in submission order; after the delete,
    GetResource answers ResourceNotFoundException with the handler's not-found message."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    name = ctx.unique_name("sim2real-behav-ccapi-param-")

    ctx.on_cleanup(lambda: _delete_resource(cc, _TYPE_NAME, name, teardown))

    # 1. CREATE
    create_event = cc.create_resource(
        TypeName=_TYPE_NAME,
        DesiredState=json.dumps({"Name": name, "Type": "String", "Value": "v1"}),
    )["ProgressEvent"]
    create_final = _poll_request_terminal(cc, create_event["RequestToken"])
    assert create_final["OperationStatus"] == "SUCCESS", create_final
    identifier = create_final["Identifier"]
    assert identifier == name, f"expected created identifier to be {name}, got {identifier}"

    # 2. UPDATE
    update_event = cc.update_resource(
        TypeName=_TYPE_NAME,
        Identifier=identifier,
        PatchDocument=json.dumps([{"op": "replace", "path": "/Value", "value": "v2"}]),
    )["ProgressEvent"]
    update_final = _poll_request_terminal(cc, update_event["RequestToken"])
    assert update_final["OperationStatus"] == "SUCCESS", update_final

    # 3. DELETE
    delete_event = cc.delete_resource(TypeName=_TYPE_NAME, Identifier=identifier)["ProgressEvent"]
    delete_final = _poll_request_terminal(cc, delete_event["RequestToken"])
    assert delete_final["OperationStatus"] == "SUCCESS", delete_final

    # 3b. The delete must be real: an independent read (GetResource, not another
    # ListResourceRequests poll) must report the identifier gone.
    from botocore.exceptions import ClientError

    try:
        cc.get_resource(TypeName=_TYPE_NAME, Identifier=identifier)
        raise AssertionError(f"expected {identifier} to be gone after delete, but GetResource still returns it")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException reading {identifier} after delete, got {code}"
        )
        message = exc.response["Error"].get("Message", "")
        expected = _handler_not_found(
            message,
            f"{_TYPE_NAME} Handler returned status FAILED: Resource of type '{_TYPE_NAME}' "
            f"with identifier '{identifier}' was not found.",
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    # 4. Collect every ListResourceRequests entry for this identifier. The service does
    # not document a guaranteed return order for the page contents, so establish
    # submission chronology from each entry's own EventTime (the authoritative ordering
    # field) rather than assuming the raw list order is chronological.
    summaries = _list_all_requests_for_identifier(cc, identifier)
    assert len(summaries) >= 3, f"expected at least 3 entries for {identifier}, got {summaries}"
    ordered = sorted(summaries, key=lambda s: s["EventTime"])[:3]
    operations = [s["Operation"] for s in ordered]
    assert operations == ["CREATE", "UPDATE", "DELETE"], f"unexpected order: {summaries}"
    request_tokens = [s["RequestToken"] for s in ordered]
    assert request_tokens == [
        create_event["RequestToken"],
        update_event["RequestToken"],
        delete_event["RequestToken"],
    ], f"request tokens not in submission order: {summaries}"


def _poll_request_terminal(cc: Any, request_token: str, timeout_s: float = 90.0, interval_s: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if last.get("OperationStatus") in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {request_token} did not reach a terminal state in {timeout_s}s: {last}")


def _list_all_requests_for_identifier(cc: Any, identifier: str) -> list[dict]:
    matches: list[dict] = []
    next_token = None
    for _ in range(20):
        kwargs = {"MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cc.list_resource_requests(**kwargs)
        for summary in resp.get("ResourceRequestStatusSummaries", []):
            if summary.get("Identifier") == identifier and summary.get("TypeName") == _TYPE_NAME:
                matches.append(summary)
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return matches


#: A RequestToken: a lowercase UUID.
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _handler_not_found(message, detail):
    """The handler's NotFound text; its RequestToken (a UUID) is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    token = token if re.fullmatch(_UUID, token) else "<a UUID>"
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"


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
