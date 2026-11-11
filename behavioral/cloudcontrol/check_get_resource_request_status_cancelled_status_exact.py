"""get-resource-request-status-cancelled-status-exact."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-resource-request-status-cancelled-status-exact"
GROUP = "error-semantics"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Cancelling an in-flight DynamoDB table create ends in exactly CANCEL_COMPLETE, and the
    table is absent from ListTables, DescribeTable and Cloud Control GetResource."""
    cc = ctx.client("cloudcontrol")
    ddb = ctx.client("dynamodb")

    table_name = ctx.unique_name("sim2real-behav-cccancel-")
    desired_state = json.dumps(
        {
            "TableName": table_name,
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "BillingMode": "PAY_PER_REQUEST",
            "Tags": [{"Key": "sim2real", "Value": CHECK}],
        }
    )
    create_progress = cc.create_resource(TypeName="AWS::DynamoDB::Table", DesiredState=desired_state)[
        "ProgressEvent"
    ]
    token = create_progress["RequestToken"]
    ctx.on_cleanup(lambda: _delete_table_if_exists(ddb, table_name))

    # Table creation takes many seconds to stabilize -- cancel promptly, while it
    # is still PENDING/IN_PROGRESS.
    cancel_progress = cc.cancel_resource_request(RequestToken=token)["ProgressEvent"]
    assert cancel_progress["OperationStatus"] in ("CANCEL_IN_PROGRESS", "CANCEL_COMPLETE"), (
        f"expected CancelResourceRequest to accept the in-flight request with a CANCEL_* status, "
        f"got {cancel_progress!r}"
    )

    final = _poll_request_status(ctx, token)
    assert final["OperationStatus"] == "CANCEL_COMPLETE", (
        f"expected the terminal status to be exactly CANCEL_COMPLETE, not a generic FAILED or an "
        f"unresolved terminal state: {final!r}"
    )

    # The status alone does not prove the cancel took effect; check DynamoDB itself.
    listed = []
    for page in ddb.get_paginator("list_tables").paginate():
        listed.extend(page["TableNames"])
    assert table_name not in listed, (
        f"the cancelled create left {table_name!r} visible in DynamoDB ListTables "
        f"({len(listed)} tables total): CANCEL_COMPLETE was reported but had no real effect"
    )
    describe_code, describe_message = _error(lambda: ddb.describe_table(TableName=table_name))
    assert describe_code == "ResourceNotFoundException", (
        f"expected DynamoDB DescribeTable to answer ResourceNotFoundException for a table whose "
        f"create was cancelled, got {describe_code!r}"
    )
    assert describe_message == f"Requested resource not found: Table: {table_name} not found", (
        f"expected DynamoDB's exact not-found message for {table_name!r}, got {describe_message!r}"
    )
    # message varies: the handler embeds its own per-call RequestToken, which the check never sees
    cc_code, _ = _error(
        lambda: cc.get_resource(TypeName="AWS::DynamoDB::Table", Identifier=table_name)
    )
    assert cc_code == "ResourceNotFoundException", (
        f"expected Cloud Control's own GetResource to also report the table absent after the "
        f"cancel, got {cc_code!r}"
    )


def _delete_table_if_exists(ddb, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _error(fn):
    """The AWS (code, message) raised by fn(); raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _poll_request_status(ctx, token, timeout_s=180.0, interval_s=3.0):
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    last = None
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if last["OperationStatus"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} never reached a terminal status; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
