"""list-resources-pagination-stable-ordering."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-resources-pagination-stable-ordering"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]

_TYPE_NAME = "AWS::SQS::Queue"
_NUM_QUEUES = 12
_PREFIX = "sim2real-cc-pg-"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListResources for AWS::SQS::Queue lists all twelve queues this run created with no
    identifier repeated, in the same relative order across two full traversals, and an unregistered
    TypeName is refused with TypeNotFoundException and "The type '<name>' cannot be found."."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()

    names = [ctx.unique_name(_PREFIX) for _ in range(_NUM_QUEUES)]
    tokens = []
    for name in names:
        resp = cc.create_resource(
            TypeName=_TYPE_NAME,
            DesiredState=json.dumps({"QueueName": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}),
        )
        tokens.append(resp["ProgressEvent"]["RequestToken"])

    terminal = _wait_all(cc, tokens)
    expected_identifiers = set()
    for token in tokens:
        pe = terminal[token]
        assert pe["OperationStatus"] == "SUCCESS", f"queue create failed: {pe}"
        identifier = pe["Identifier"]
        expected_identifiers.add(identifier)
        ctx.on_cleanup(lambda ident=identifier: _delete_resource(cc, _TYPE_NAME, ident, teardown))

    assert len(expected_identifiers) == _NUM_QUEUES, "expected each created queue to have a distinct identifier"

    first_ids = _paginate_all(cc, _TYPE_NAME)
    seen_set: set[str] = set()
    duplicates: list[str] = []
    for ident in first_ids:
        if ident in seen_set:
            duplicates.append(ident)
        seen_set.add(ident)

    assert not duplicates, f"ListResources returned duplicate identifiers across pages: {duplicates[:5]}"

    missing = expected_identifiers - seen_set
    assert not missing, f"ListResources pagination skipped {len(missing)} created queues: {sorted(missing)[:5]}"

    # Other queues in the Region can come and go between the two traversals, so only the
    # relative order of this run's own queues is compared.
    second_ids = _paginate_all(cc, _TYPE_NAME)
    mine_first = [i for i in first_ids if i in expected_identifiers]
    mine_second = [i for i in second_ids if i in expected_identifiers]
    assert mine_second == mine_first, (
        "ListResources pagination order for this run's own queues was not stable across two "
        f"independent full traversals: {mine_first} != {mine_second}"
    )

    # ListResources against a plausible but unregistered resource type is refused up front,
    # not treated as an empty filter.
    from botocore.exceptions import ClientError

    try:
        cc.list_resources(TypeName="Sim2Real::NotReal::Type")
        raise AssertionError("expected ListResources against an unregistered TypeName to be rejected")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "TypeNotFoundException", (
            f"expected TypeNotFoundException for an unregistered TypeName, got {code}"
        )
        message = e.response["Error"].get("Message")
        assert message == "The type 'Sim2Real::NotReal::Type' cannot be found.", (
            f"expected the type-not-found message naming the TypeName, got {message!r}"
        )


_TERMINAL = ("SUCCESS", "FAILED", "CANCEL_COMPLETE")
_MAX_PAGES = 2000


def _paginate_all(cc, type_name, page_size=50):
    # The listing can hold many unrelated queues; a larger page keeps the two full walks short.
    ids: list[str] = []
    next_token = None
    for _ in range(_MAX_PAGES):
        kwargs = {"TypeName": type_name, "MaxResults": page_size}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cc.list_resources(**kwargs)
        ids.extend(rd["Identifier"] for rd in resp.get("ResourceDescriptions", []))
        next_token = resp.get("NextToken")
        if not next_token:
            return ids
    raise AssertionError(f"ListResources pagination did not terminate within {_MAX_PAGES} pages")


def _wait_all(cc, tokens, timeout_s=180.0, interval_s=2.0):
    pending = set(tokens)
    results = {}
    deadline = time.monotonic() + timeout_s
    while pending and time.monotonic() < deadline:
        for token in list(pending):
            pe = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
            if pe["OperationStatus"] in _TERMINAL:
                results[token] = pe
                pending.discard(token)
        if pending:
            time.sleep(interval_s)
    if pending:
        raise AssertionError(f"{len(pending)} create requests never reached a terminal state")
    return results


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
