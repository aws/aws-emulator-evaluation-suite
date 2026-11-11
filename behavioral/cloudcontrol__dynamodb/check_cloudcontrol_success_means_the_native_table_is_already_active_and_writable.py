"""cloudcontrol-success-means-the-native-table-is-already-active-and-writable."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-success-means-the-native-table-is-already-active-and-writable"
GROUP = "native-truth"
SERVICES = ["cloudcontrol", "dynamodb"]

TABLE_TYPE = "AWS::DynamoDB::Table"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """At the first Cloud Control SUCCESS the DynamoDB table is already ACTIVE and writable, and
    after the delete SUCCESS it is already gone: SUCCESS means the resource has stabilized."""
    cc = ctx.client("cloudcontrol")
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ccstab-")

    desired_state = _table_desired_state(table)
    submitted = cc.create_resource(TypeName=TABLE_TYPE, DesiredState=desired_state)
    # Registered before the first assertion: a FAILED terminal event can still have left a real
    # table behind, and the only reapable handle is the DynamoDB name, not the request token.
    ctx.on_cleanup(lambda: _delete_table_quiet(ddb, table))

    create_token = submitted["ProgressEvent"]["RequestToken"]
    initial_status = submitted["ProgressEvent"]["OperationStatus"]
    # The asynchrony witness: CreateResource's own answer is the non-terminal status that opens
    # the sequence before SUCCESS, even for a table already ACTIVE by the first poll.
    assert initial_status not in TERMINAL_STATUSES, (
        f"CreateResource answered terminal status {initial_status!r} in its own response; a "
        f"DynamoDB table cannot be provisioned synchronously, so the request must come back "
        f"non-terminal (one of PENDING/IN_PROGRESS); a target that completes it synchronously "
        f"has no ProgressEvent state machine at all"
    )

    polled, terminal = _poll_statuses(
        cc, create_token, timeout_s=120.0, interval_s=2.0, reason="the table create to terminate"
    )
    observed = [initial_status, *polled]
    assert terminal["OperationStatus"] == "SUCCESS", (
        f"create terminated {terminal['OperationStatus']!r} with ErrorCode "
        f"{terminal.get('ErrorCode')!r} / StatusMessage {terminal.get('StatusMessage')!r}, "
        f"expected SUCCESS; full status sequence {observed}"
    )

    # Deliberately not retried: SUCCESS means stabilization already finished.
    at_success = ddb.describe_table(TableName=table)["Table"]
    assert at_success["TableStatus"] == "ACTIVE", (
        f"Cloud Control reported SUCCESS but DynamoDB reports TableStatus "
        f"{at_success['TableStatus']!r} for {table!r}; SUCCESS must mean stabilization completed, "
        f"so ACTIVE must already hold with no further waiting"
    )
    assert terminal.get("Identifier") == table, (
        f"the SUCCESS ProgressEvent reports Identifier {terminal.get('Identifier')!r}, the "
        f"desired state asked for TableName {table!r}"
    )

    ddb.put_item(
        TableName=table,
        Item={"pk": {"S": "row-1"}, "payload": {"S": CHECK}},
    )
    fetched = ddb.get_item(
        TableName=table, Key={"pk": {"S": "row-1"}}, ConsistentRead=True
    )
    assert "Item" in fetched, (
        f"a table Cloud Control reported ACTIVE via SUCCESS did not return the item just written; "
        f"get_item answered keys {sorted(fetched)}"
    )
    assert fetched["Item"]["payload"]["S"] == CHECK, (
        f"DynamoDB returned payload {fetched['Item']['payload']['S']!r}, expected {CHECK!r}"
    )

    # Reads of a settled request must not advance its record.
    frozen = [
        cc.get_resource_request_status(RequestToken=create_token)["ProgressEvent"]
        for _ in range(3)
    ]
    signatures = {
        (e["OperationStatus"], str(e["EventTime"]), e.get("Identifier")) for e in frozen
    }
    assert len(signatures) == 1, (
        f"three consecutive GetResourceRequestStatus reads of one settled request returned "
        f"{len(signatures)} distinct (OperationStatus, EventTime, Identifier) signatures "
        f"{sorted(signatures)}; a read must not advance the request record"
    )
    settled = frozen[0]
    assert settled["OperationStatus"] == "SUCCESS", (
        f"the settled request now reports {settled['OperationStatus']!r}, it reported SUCCESS "
        f"moments earlier"
    )
    assert str(settled["EventTime"]) == str(terminal["EventTime"]), (
        f"EventTime moved from {terminal['EventTime']!r} to {settled['EventTime']!r} across "
        f"reads alone"
    )

    removed = cc.delete_resource(TypeName=TABLE_TYPE, Identifier=table)
    delete_observed, delete_terminal = _poll_statuses(
        cc,
        removed["ProgressEvent"]["RequestToken"],
        timeout_s=120.0,
        interval_s=2.0,
        reason="the table delete to terminate",
    )
    assert delete_terminal["OperationStatus"] == "SUCCESS", (
        f"delete terminated {delete_terminal['OperationStatus']!r} with ErrorCode "
        f"{delete_terminal.get('ErrorCode')!r}, expected SUCCESS; sequence {delete_observed}"
    )
    gone_code, gone_message = _error(lambda: ddb.describe_table(TableName=table))
    assert gone_code == "ResourceNotFoundException", (
        f"Cloud Control reported the delete SUCCESS but DynamoDB answers {gone_code!r} for "
        f"{table!r}, expected ResourceNotFoundException; SUCCESS must mean the table is already "
        f"gone, not still DELETING"
    )
    expected_gone = f"Requested resource not found: Table: {table} not found"
    assert gone_message == expected_gone, (
        f"describe_table of the deleted table answered message {gone_message!r}, expected "
        f"{expected_gone!r}"
    )
    write_code, write_message = _error(
        lambda: ddb.put_item(TableName=table, Item={"pk": {"S": "row-2"}})
    )
    assert write_code == "ResourceNotFoundException", (
        f"a write to the deleted table answered {write_code!r}, expected "
        f"ResourceNotFoundException; the put_item that demonstrably worked earlier must now fail"
    )
    assert write_message == "Requested resource not found", (
        f"put_item on the deleted table answered message {write_message!r}, expected "
        f"'Requested resource not found'"
    )
    # message varies: Cloud Control embeds a server-generated RequestToken in the
    # GetResource NotFound message, and that token is returned nowhere else in the response.
    cc_code, _ = _error(lambda: cc.get_resource(TypeName=TABLE_TYPE, Identifier=table))
    assert cc_code == "ResourceNotFoundException", (
        f"Cloud Control GetResource answers {cc_code!r} for the deleted table, expected "
        f"ResourceNotFoundException"
    )


def _table_desired_state(table: str) -> str:
    """PAY_PER_REQUEST so nothing is provisioned by the hour; one string hash key is the
    cheapest table that still has a real CREATING -> ACTIVE stabilization phase."""
    return json.dumps(
        {
            "TableName": table,
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "BillingMode": "PAY_PER_REQUEST",
            "Tags": [{"Key": "sim2real", "Value": CHECK}],
        }
    )


def _poll_statuses(cc, request_token, *, timeout_s, interval_s, reason):
    """Poll GetResourceRequestStatus to a terminal OperationStatus; return the observed sequence
    and the terminal event, raising on timeout."""
    observed: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        event = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        observed.append(event["OperationStatus"])
        if event["OperationStatus"] in TERMINAL_STATUSES:
            return observed, event
        time.sleep(interval_s)
    raise AssertionError(
        f"waited {timeout_s}s for {reason} and it never reached a terminal OperationStatus; "
        f"observed {observed}"
    )


def _error(fn):
    """The AWS error (code, message) raised by fn(); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _delete_table_quiet(ddb, table):
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
