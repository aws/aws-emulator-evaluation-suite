"""cloudcontrol-downstream-handler-rejected-create-leaves-no-native-table."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-downstream-handler-rejected-create-leaves-no-native-table"
GROUP = 'native-truth'
SERVICES = ['cloudcontrol']
DDB_TABLE_TYPE = "AWS::DynamoDB::Table"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


def _poll_until(probe, predicate, *, timeout_s=180, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_terminal(cc, request_token, *, timeout_s=180, interval_s=3.0):
    """Poll GetResourceRequestStatus to a terminal OperationStatus; return the ProgressEvent."""
    return _poll_until(
        lambda: cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"],
        lambda e: e is not None and e.get("OperationStatus") in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"request {request_token} reaching a terminal OperationStatus",
    )


def _client_error(fn):
    """The AWS (error code, message) raised by fn(); raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _drop_table_quiet(ddb, name):
    try:
        ddb.delete_table(TableName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _table(name, key_attribute):
    return json.dumps({
        "TableName": name,
        "KeySchema": [{"AttributeName": key_attribute, "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    })


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A schema-valid create that the DynamoDB handler rejects ends FAILED with InvalidRequest.

    No table is left behind; the corrected request creates a table that round-trips an item.
    """
    cc = ctx.client("cloudcontrol")
    ddb = ctx.client("dynamodb")

    # The KeySchema names an attribute AttributeDefinitions lacks; only the handler catches this.
    name = ctx.unique_name("sim2real-behav-ccbadks-")
    refused = cc.create_resource(TypeName=DDB_TABLE_TYPE, DesiredState=_table(name, "nosuch"))
    # Registered before the first assertion: if the handler wrongly accepts this, a real table
    # exists and its only reapable handle is the DynamoDB table name.
    ctx.on_cleanup(lambda: _drop_table_quiet(ddb, name))
    terminal = _wait_terminal(cc, refused["ProgressEvent"]["RequestToken"])
    assert terminal["OperationStatus"] == "FAILED", (
        f"a create whose KeySchema references an undefined attribute reached {terminal!r}"
    )
    assert terminal["ErrorCode"] == "InvalidRequest", (
        f"the refusal carried ErrorCode {terminal.get('ErrorCode')!r}, expected 'InvalidRequest'"
    )
    message = terminal.get("StatusMessage")
    expected = "An attribute referenced in a KeySchema element is not defined in AttributeDefinitions"
    assert message == expected, (
        f"the StatusMessage does not carry the downstream handler's own diagnosis: {message!r}"
    )

    listed = []
    for page in ddb.get_paginator("list_tables").paginate():
        listed.extend(page["TableNames"])
    assert name not in listed, (
        f"the refused create left a table in DynamoDB; ListTables holds {len(listed)!r} tables "
        f"including {name!r}"
    )
    describe_code, describe_message = _client_error(lambda: ddb.describe_table(TableName=name))
    assert describe_code == "ResourceNotFoundException", (
        f"DynamoDB DescribeTable answered {describe_code!r} for a table whose create was refused"
    )
    expected_describe = f"Requested resource not found: Table: {name} not found"
    assert describe_message == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_message!r}"
    )

    control_name = ctx.unique_name("sim2real-behav-ccctl-")
    control = cc.create_resource(TypeName=DDB_TABLE_TYPE, DesiredState=_table(control_name, "pk"))
    ctx.on_cleanup(lambda: _drop_table_quiet(ddb, control_name))
    control_event = _wait_terminal(cc, control["ProgressEvent"]["RequestToken"])
    assert control_event["OperationStatus"] == "SUCCESS", (
        f"positive control create failed: {control_event!r}"
    )
    _poll_until(
        lambda: ddb.describe_table(TableName=control_name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        description=f"DynamoDB table {control_name} becoming ACTIVE",
    )
    ddb.put_item(TableName=control_name,
                 Item={"pk": {"S": "row-1"}, "payload": {"S": "via-cloudcontrol"}})
    item = ddb.get_item(TableName=control_name, Key={"pk": {"S": "row-1"}}, ConsistentRead=True)
    assert item["Item"]["payload"]["S"] == "via-cloudcontrol", (
        f"the table Cloud Control created does not round-trip an item: {item.get('Item')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
