"""server-side-progress-events-tracked-per-request-dup-removed."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-progress-events-tracked-per-request-dup-removed"
GROUP = "server-side"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every GetResourceRequestStatus poll of one queue-create RequestToken reports the same token,
    TypeName and Operation until SUCCESS with the Identifier, and ListResourceRequests filtered to
    CREATE/SUCCESS lists that request exactly once with the same Identifier and TypeName."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    queue_name = ctx.unique_name("sim2real-cc-progress2-")
    resp = cc.create_resource(
        TypeName="AWS::SQS::Queue", DesiredState=json.dumps({"QueueName": queue_name})
    )
    pe0 = resp["ProgressEvent"]
    token = pe0["RequestToken"]
    assert pe0["TypeName"] == "AWS::SQS::Queue", f"expected TypeName AWS::SQS::Queue, got {pe0['TypeName']!r}"
    assert pe0["Operation"] == "CREATE", f"expected Operation CREATE, got {pe0['Operation']!r}"
    assert pe0["OperationStatus"] in ("PENDING", "IN_PROGRESS", "SUCCESS"), (
        f"unexpected initial OperationStatus: {pe0['OperationStatus']!r}"
    )

    statuses_seen = [pe0["OperationStatus"]]
    identifier = None
    final = None
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        status_resp = cc.get_resource_request_status(RequestToken=token)
        pe = status_resp["ProgressEvent"]
        # every poll against the same token must describe the same underlying request
        assert pe["RequestToken"] == token, f"RequestToken changed across polls: {token!r} -> {pe['RequestToken']!r}"
        assert pe["TypeName"] == "AWS::SQS::Queue", f"expected TypeName AWS::SQS::Queue, got {pe['TypeName']!r}"
        assert pe["Operation"] == "CREATE", f"expected Operation CREATE, got {pe['Operation']!r}"
        statuses_seen.append(pe["OperationStatus"])
        if pe.get("Identifier"):
            identifier = pe["Identifier"]
        if pe["OperationStatus"] in ("SUCCESS", "FAILED"):
            final = pe
            break
        time.sleep(2.0)

    assert final is not None and final["OperationStatus"] == "SUCCESS", (
        f"create request never reached SUCCESS, statuses observed: {statuses_seen}"
    )
    assert identifier, "SUCCESS progress event did not carry the created resource Identifier"
    ctx.on_cleanup(lambda: _delete_resource(cc, "AWS::SQS::Queue", identifier, teardown))

    # ListResourceRequests can lag GetResourceRequestStatus, so it is polled; other requests can
    # push this entry past the first page, so each poll walks every page.
    matches: list[dict] = []
    list_deadline = time.monotonic() + 60.0
    while time.monotonic() < list_deadline:
        matches = [
            s
            for s in _list_all_requests(
                cc, operations=["CREATE"], statuses=["SUCCESS"]
            )
            if s["RequestToken"] == token
        ]
        if matches:
            break
        time.sleep(2.0)
    assert len(matches) == 1, (
        f"expected exactly one CREATE/SUCCESS entry for {token!r} via ListResourceRequests, "
        f"found {len(matches)}: {matches}"
    )
    assert matches[0]["Identifier"] == identifier, (
        f"ListResourceRequests Identifier {matches[0]['Identifier']!r} != GetResourceRequestStatus "
        f"Identifier {identifier!r}"
    )
    assert matches[0]["TypeName"] == "AWS::SQS::Queue", (
        f"expected TypeName AWS::SQS::Queue in listing, got {matches[0]['TypeName']!r}"
    )


def _list_all_requests(
    cc: Any,
    operations: list[str] | None = None,
    statuses: list[str] | None = None,
    max_pages: int = 50,
    max_results: int = 100,
) -> list[dict]:
    out: list[dict] = []
    next_token = None
    filt: dict[str, Any] = {}
    if operations:
        filt["Operations"] = operations
    if statuses:
        filt["OperationStatuses"] = statuses
    for _ in range(max_pages):
        kwargs: dict[str, Any] = {"MaxResults": max_results}
        if filt:
            kwargs["ResourceRequestStatusFilter"] = filt
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cc.list_resource_requests(**kwargs)
        out.extend(resp.get("ResourceRequestStatusSummaries", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return out


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
