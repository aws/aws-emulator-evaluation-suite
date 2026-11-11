"""request-visible-in-list-before-completion."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "request-visible-in-list-before-completion"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]

_TERMINAL = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
_NONTERMINAL = {"PENDING", "IN_PROGRESS", "CANCEL_IN_PROGRESS"}
_KNOWN_STATUSES = _TERMINAL | _NONTERMINAL


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly submitted request is discoverable via ListResourceRequests as soon as
    CreateResource returns, without the caller having to wait for the request to reach
    a terminal status, and the status observed there is never ahead of the eventual outcome."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-cc-vis-")
    resp = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps(
            {"QueueName": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ),
    )
    token = resp["ProgressEvent"]["RequestToken"]
    submit_status = resp["ProgressEvent"]["OperationStatus"]
    assert submit_status in _KNOWN_STATUSES, f"unexpected initial OperationStatus: {submit_status}"

    # query ListResourceRequests immediately -- no wait for the operation to finish
    immediate = _find_one(ctx, token)
    assert immediate is not None, (
        "the just-submitted request token was not found in ListResourceRequests "
        "immediately after CreateResource returned"
    )
    immediate_status = immediate["OperationStatus"]
    assert immediate_status in _KNOWN_STATUSES, (
        f"unrecognized OperationStatus in list snapshot: {immediate_status!r}"
    )

    final_pe, _ = _wait_for_request(ctx, token)
    ctx.on_cleanup(lambda i=final_pe["Identifier"]: _delete_and_wait(ctx, "AWS::SQS::Queue", i))
    assert final_pe["OperationStatus"] == "SUCCESS", f"create did not reach SUCCESS: {final_pe}"

    # the pre-completion snapshot must not report a terminal outcome that differs from
    # what the request actually settles as -- a non-terminal snapshot is always consistent
    # (it has not yet decided), but a terminal one is a claim that must hold up
    if immediate_status in _TERMINAL:
        assert immediate_status == final_pe["OperationStatus"], (
            f"list snapshot reported terminal status {immediate_status!r} but the request "
            f"actually settled as {final_pe['OperationStatus']!r} -- the pre-completion "
            f"snapshot must not report a different terminal outcome than the one the request "
            f"eventually reaches"
        )

    # the request remains listed, now reflecting the terminal outcome
    after = _find_one(ctx, token)
    assert after is not None and after["OperationStatus"] == "SUCCESS", (
        f"expected the request to remain listed with terminal status SUCCESS after "
        f"completion, got {after!r}"
    )


def _wait_for_request(ctx: Any, token: str, timeout_s: float = 150.0, interval_s: float = 2.0):
    cc = ctx.client("cloudcontrol")
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    history: list[str] = []
    deadline = time.monotonic() + timeout_s
    last_pe = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last_pe = resp["ProgressEvent"]
        history.append(last_pe["OperationStatus"])
        if last_pe["OperationStatus"] in terminal:
            return last_pe, history
        time.sleep(interval_s)
    raise AssertionError(f"request {token} did not reach a terminal state within {timeout_s}s (history={history})")


def _delete_and_wait(ctx: Any, type_name: str, identifier: str, timeout_s: float = 150.0, interval_s: float = 2.0) -> None:
    cc = ctx.client("cloudcontrol")
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise
        return
    token = resp["ProgressEvent"]["RequestToken"]
    _wait_for_request(ctx, token, timeout_s=timeout_s, interval_s=interval_s)


def _list_all_requests(ctx: Any, operations=None, statuses=None, max_pages: int = 50, max_results: int = 100):
    cc = ctx.client("cloudcontrol")
    out: list[dict[str, Any]] = []
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


def _find_one(ctx: Any, token: str, max_pages: int = 50):
    for s in _list_all_requests(ctx, max_pages=max_pages):
        if s.get("RequestToken") == token:
            return s
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
