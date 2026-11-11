"""list-resource-requests-and-get-status-agree-on-one-request."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-resource-requests-and-get-status-agree-on-one-request"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]

TABLE_TYPE = "AWS::DynamoDB::Table"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
AGREED_FIELDS = ("RequestToken", "TypeName", "Operation", "OperationStatus", "Identifier")


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Once an async DynamoDB table create settles, ListResourceRequests and
    GetResourceRequestStatus report field-identical ProgressEvents that repeated reads do not
    change, and the table is ACTIVE.

    Reference: https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/API_ListResourceRequests.html
    """
    cc = ctx.client("cloudcontrol")
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ccviews-")

    submitted = cc.create_resource(
        TypeName=TABLE_TYPE, DesiredState=_table_desired_state(table)
    )
    # Native teardown: a polled Cloud Control DeleteResource would add minutes of waiting.
    ctx.on_cleanup(lambda: _delete_table_quiet(ddb, table))
    token = submitted["ProgressEvent"]["RequestToken"]

    # ---- the request really is asynchronous ---------------------------------------------------
    first_poll = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
    assert first_poll["OperationStatus"] not in TERMINAL_STATUSES, (
        f"the first GetResourceRequestStatus poll already reports "
        f"{first_poll['OperationStatus']!r}; a DynamoDB table cannot be provisioned synchronously, "
        f"so an in-flight request must still be PENDING or IN_PROGRESS here"
    )
    assert first_poll["RequestToken"] == token, (
        f"GetResourceRequestStatus echoed RequestToken {first_poll['RequestToken']!r}, the request "
        f"was submitted as {token!r}"
    )
    assert first_poll["Operation"] == "CREATE", (
        f"the in-flight event reports Operation {first_poll['Operation']!r}, expected 'CREATE'"
    )

    settled = _wait_terminal(cc, token, timeout_s=120.0)
    assert settled["OperationStatus"] == "SUCCESS", (
        f"the create terminated {settled['OperationStatus']!r} with ErrorCode "
        f"{settled.get('ErrorCode')!r} / StatusMessage {settled.get('StatusMessage')!r}, expected "
        f"SUCCESS"
    )

    # ---- the two views are one record ---------------------------------------------------------
    listed = _poll_until(
        lambda: _find_in_list(cc, token),
        lambda entry: entry is not None,
        timeout_s=60.0,
        interval_s=3.0,
        reason=(
            f"ListResourceRequests filtered to Operations=[CREATE], OperationStatuses=[SUCCESS] "
            f"to carry the settled request {token!r}"
        ),
    )
    # Pinned absolutely first, so the field-by-field agreement below cannot be satisfied by two
    # views that both omit the same field.
    assert settled["TypeName"] == TABLE_TYPE, (
        f"the settled event reports TypeName {settled['TypeName']!r}, expected {TABLE_TYPE!r}"
    )
    assert settled["Operation"] == "CREATE", (
        f"the settled event reports Operation {settled['Operation']!r}, expected 'CREATE'"
    )
    assert settled["RequestToken"] == token, (
        f"the settled event reports RequestToken {settled['RequestToken']!r}, expected {token!r}"
    )
    for field in AGREED_FIELDS:
        assert listed.get(field) == settled.get(field), (
            f"ListResourceRequests reports {field}={listed.get(field)!r} while "
            f"GetResourceRequestStatus reports {settled.get(field)!r} for the same request "
            f"{token!r}; the two views must be one record"
        )
    assert str(listed.get("EventTime")) == str(settled.get("EventTime")), (
        f"ListResourceRequests reports EventTime {listed.get('EventTime')!r} while "
        f"GetResourceRequestStatus reports {settled.get('EventTime')!r} for the same request; a "
        f"re-derived timestamp means the list entry is synthesised, not the record itself"
    )
    assert listed.get("Identifier") == table, (
        f"the settled request reports Identifier {listed.get('Identifier')!r}, the desired state "
        f"asked for TableName {table!r}"
    )

    # ---- reads must not advance state ---------------------------------------------------------
    signatures = set()
    for _ in range(3):
        point = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        collection = _find_in_list(cc, token)
        assert collection is not None, (
            f"the settled request {token!r} vanished from ListResourceRequests between reads; a "
            f"terminal request record must be retained"
        )
        signatures.add(
            (
                point["OperationStatus"],
                str(point["EventTime"]),
                point.get("Identifier"),
                collection["OperationStatus"],
                str(collection["EventTime"]),
                collection.get("Identifier"),
            )
        )
    assert len(signatures) == 1, (
        f"three consecutive (GetResourceRequestStatus, ListResourceRequests) read pairs of one "
        f"settled request produced {len(signatures)} distinct signatures {sorted(signatures)}; "
        f"reading a request must not change it"
    )

    # ---- the destination confirms the request was real ---------------------------------------
    described = ddb.describe_table(TableName=table)["Table"]
    assert described["TableStatus"] == "ACTIVE", (
        f"the request both views agree succeeded left DynamoDB reporting TableStatus "
        f"{described['TableStatus']!r} for {table!r}, expected ACTIVE"
    )
    assert described["TableName"] == table, (
        f"DynamoDB reports TableName {described['TableName']!r}, expected {table!r}"
    )


def _table_desired_state(table: str) -> str:
    """The cheapest on-demand table that still has a several-second CREATING phase to observe."""
    return json.dumps(
        {
            "TableName": table,
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "BillingMode": "PAY_PER_REQUEST",
            "Tags": [{"Key": "sim2real", "Value": CHECK}],
        }
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, reason):
    """Poll probe() until predicate holds and return the value; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"waited {timeout_s}s for {reason} and it never happened; last observation {last!r}"
    )


def _wait_terminal(cc, request_token, *, timeout_s=90.0, interval_s=2.0):
    """Poll GetResourceRequestStatus to a terminal OperationStatus; return the ProgressEvent."""
    return _poll_until(
        lambda: cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"],
        lambda event: event is not None and event["OperationStatus"] in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        reason=f"request {request_token} to reach a terminal OperationStatus",
    )


def _find_in_list(cc, request_token):
    """The ProgressEvent ListResourceRequests (CREATE/SUCCESS filter) reports for a token, or None.

    Pagination is bounded so a broken NextToken raises rather than looping."""
    kwargs = {
        "ResourceRequestStatusFilter": {
            "Operations": ["CREATE"],
            "OperationStatuses": ["SUCCESS"],
        },
        "MaxResults": 100,
    }
    for _ in range(50):
        resp = cc.list_resource_requests(**kwargs)
        for summary in resp.get("ResourceRequestStatusSummaries", []):
            if summary.get("RequestToken") == request_token:
                return summary
        token = resp.get("NextToken")
        if not token:
            return None
        kwargs["NextToken"] = token
    raise AssertionError(
        "ListResourceRequests still returned a NextToken after 50 pages; pagination is not "
        "terminating"
    )


def _delete_table_quiet(ddb, table):
    """Teardown, scoped to the one table this check created."""
    try:
        ddb.delete_table(TableName=table)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
