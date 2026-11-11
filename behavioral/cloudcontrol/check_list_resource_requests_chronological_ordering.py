"""list-resource-requests-chronological-ordering."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-resource-requests-chronological-ordering"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]

_TYPE_NAME = "AWS::SQS::Queue"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResourceRequests reports a CREATE then an UPDATE on the same resource in the
    actual chronological order they were submitted, not reversed or shuffled."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-cc-order-")

    create_resp = cc.create_resource(
        TypeName=_TYPE_NAME,
        DesiredState=json.dumps(
            {"QueueName": name, "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}
        ),
    )
    create_token = create_resp["ProgressEvent"]["RequestToken"]
    create_pe = _wait_for_terminal(cc, create_token)
    assert create_pe["OperationStatus"] == "SUCCESS", f"create did not succeed: {create_pe}"
    identifier = create_pe["Identifier"]
    ctx.on_cleanup(lambda: _cleanup_delete(cc, _TYPE_NAME, identifier))

    # Wait for the CREATE's own entry to become visible in ListResourceRequests before
    # submitting the UPDATE. This is a real precondition -- the create is now durably
    # recorded with its own EventTime -- not an arbitrary delay: it guarantees the two
    # requests are chronologically separated by an observed side effect rather than a
    # blind sleep hoping enough wall-clock time has passed.
    _wait_until_visible(cc, identifier, create_token)

    update_resp = cc.update_resource(
        TypeName=_TYPE_NAME,
        Identifier=identifier,
        PatchDocument=json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 45}]),
    )
    update_token = update_resp["ProgressEvent"]["RequestToken"]
    update_pe = _wait_for_terminal(cc, update_token)
    assert update_pe["OperationStatus"] == "SUCCESS", f"update did not succeed: {update_pe}"

    entries, filtered = _poll_for_entries(cc, identifier, expected_count=2)
    assert len(filtered) == 2, f"expected 2 ListResourceRequests entries for {identifier}, got {len(filtered)}"

    create_entry = next(e for e in filtered if e.get("RequestToken") == create_token)
    update_entry = next(e for e in filtered if e.get("RequestToken") == update_token)

    # The service does not guarantee a specific listing direction (newest-first vs
    # oldest-first), but the EventTime it reports MUST truthfully reflect the actual
    # submission order: the create genuinely happened before the update.
    assert create_entry["EventTime"] < update_entry["EventTime"], (
        f"EventTime for the CREATE ({create_entry['EventTime']}) is not before the "
        f"EventTime for the UPDATE ({update_entry['EventTime']}) that was submitted later "
        f"-- reported chronology contradicts actual submission order"
    )

    # And the full page of results must itself be internally consistent for entries
    # belonging to this resource (sorted by EventTime in one single direction), not
    # arbitrarily shuffled. We only check the entries for our own identifier, since a
    # shared verification account may have unrelated concurrent activity interleaved.
    identifier_positions = [i for i, e in enumerate(entries) if e.get("Identifier") == identifier]
    identifier_times = [entries[i]["EventTime"] for i in identifier_positions]
    is_desc = all(identifier_times[i] >= identifier_times[i + 1] for i in range(len(identifier_times) - 1))
    is_asc = all(identifier_times[i] <= identifier_times[i + 1] for i in range(len(identifier_times) - 1))
    assert is_desc or is_asc, (
        "ListResourceRequests entries for our own identifier are not consistently "
        "ordered by EventTime in either direction -- order is arbitrary/shuffled"
    )

    # And the create/update pair's relative list positions must agree with whichever
    # single direction the listing uses.
    pos_create = next(i for i, e in enumerate(entries) if e.get("RequestToken") == create_token)
    pos_update = next(i for i, e in enumerate(entries) if e.get("RequestToken") == update_token)
    if is_asc:
        assert pos_create < pos_update, (
            f"listing is ascending by EventTime but CREATE (pos {pos_create}) does not "
            f"precede UPDATE (pos {pos_update})"
        )
    else:
        assert pos_create > pos_update, (
            f"listing is descending by EventTime but CREATE (pos {pos_create}) does not "
            f"follow UPDATE (pos {pos_update})"
        )

    # DISTINCT overly-permissive boundary: an unknown enum value in the OperationStatuses
    # filter must be rejected up front by validation, not silently accepted as a no-op
    # filter that returns everything (or nothing).
    from botocore.exceptions import ClientError

    try:
        cc.list_resource_requests(
            ResourceRequestStatusFilter={"OperationStatuses": ["NOT_A_REAL_STATUS"]}
        )
        raise AssertionError("expected an invalid OperationStatuses filter value to be rejected")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ValidationException", (
            f"expected ValidationException for an invalid OperationStatuses filter value, got {code}"
        )
        expected_message = (
            "1 validation error detected: Value '[NOT_A_REAL_STATUS]' at "
            "'resourceRequestStatusFilter.operationStatuses' failed to satisfy constraint: "
            "Member must satisfy constraint: [Member must satisfy enum value set: "
            "[CANCEL_IN_PROGRESS, SUCCESS, IN_PROGRESS, PENDING, FAILED, CANCEL_COMPLETE]]"
        )
        message = e.response["Error"].get("Message")
        assert message == expected_message, (
            f"expected the enum validation message {expected_message!r}, got {message!r}"
        )


_TERMINAL = ("SUCCESS", "FAILED", "CANCEL_COMPLETE")


def _wait_for_terminal(cc, token, timeout_s=90.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} never reached terminal state (last={last})")


def _cleanup_delete(cc, type_name, identifier):
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        _wait_for_terminal(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=30)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise


def _wait_until_visible(cc, identifier, token, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        entries = _scan_all_requests(cc)
        if any(e.get("Identifier") == identifier and e.get("RequestToken") == token for e in entries):
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"CREATE request {token} for {identifier} never became visible in ListResourceRequests within {timeout_s}s"
    )


def _scan_all_requests(cc, max_pages=20, page_size=50):
    seen = []
    token = None
    for _ in range(max_pages):
        kwargs = {"MaxResults": page_size}
        if token:
            kwargs["NextToken"] = token
        resp = cc.list_resource_requests(**kwargs)
        seen.extend(resp.get("ResourceRequestStatusSummaries", []))
        token = resp.get("NextToken")
        if not token:
            break
    return seen


def _poll_for_entries(cc, identifier, expected_count, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    entries: list = []
    filtered: list = []
    while time.monotonic() < deadline:
        entries = _scan_all_requests(cc)
        filtered = [e for e in entries if e.get("Identifier") == identifier]
        if len(filtered) >= expected_count:
            return entries, filtered
        time.sleep(interval_s)
    return entries, filtered


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
