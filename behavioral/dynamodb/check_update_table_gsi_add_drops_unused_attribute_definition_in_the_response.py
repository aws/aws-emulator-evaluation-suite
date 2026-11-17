"""update-table-gsi-add-drops-unused-attribute-definition-in-the-response."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-gsi-add-drops-unused-attribute-definition-in-the-response"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_WAIT_S = 1500.0


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_table_settled(ddb, name, timeout_s=_WAIT_S, interval_s=5.0):
    """Poll DescribeTable until the table and every index are ACTIVE."""
    deadline = time.monotonic() + timeout_s
    table = None
    while time.monotonic() < deadline:
        table = ddb.describe_table(TableName=name)["Table"]
        busy = [
            i for i in table.get("GlobalSecondaryIndexes") or [] if i.get("IndexStatus") != "ACTIVE"
        ]
        if table["TableStatus"] == "ACTIVE" and not busy:
            return table
        time.sleep(interval_s)
    raise AssertionError(f"{name} never settled to ACTIVE within {timeout_s}s; last={table!r}")


def _delete_table(ddb, name):
    def run_undo() -> None:
        try:
            ddb.delete_table(TableName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    return run_undo


@tags(
    "axis:happy-path", "cap:c1", "concern:representation", "concern:data-plane",
    "dp:api", "plane:control", "plane:data",
)
def run(ctx) -> None:
    """UpdateTable's own response already drops an AttributeDefinitions entry no live key uses
    when it adds a GSI, matching the settled DescribeTable, and the index serves a query.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-gsiresp-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_delete_table(ddb, table))
    _wait_table_settled(ddb, table)

    # Add a GSI keyed on g1, declaring an extra attribute no key (base or index) uses.
    update_resp = ddb.update_table(
        TableName=table,
        AttributeDefinitions=[
            {"AttributeName": "g1", "AttributeType": "S"},
            {"AttributeName": "unused", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexUpdates=[
            {
                "Create": {
                    "IndexName": "gsi-main",
                    "KeySchema": [{"AttributeName": "g1", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                }
            }
        ],
    )
    response_attrs = {
        a["AttributeName"]: a["AttributeType"]
        for a in update_resp["TableDescription"]["AttributeDefinitions"]
    }
    assert response_attrs == {"pk": "S", "g1": "S"}, (
        f"expected UpdateTable's own response to already drop the unused attribute, leaving "
        f"{{'pk': 'S', 'g1': 'S'}}, got {response_attrs!r}"
    )

    settled = _wait_table_settled(ddb, table)
    settled_attrs = {a["AttributeName"]: a["AttributeType"] for a in settled["AttributeDefinitions"]}
    assert settled_attrs == response_attrs, (
        f"settled DescribeTable AttributeDefinitions {settled_attrs!r} must match what "
        f"UpdateTable's own response already reported, {response_attrs!r}"
    )

    # Positive control: the index is real, not just a vanished attribute -- it serves a query,
    # polled because a GSI read is eventually consistent.
    ddb.put_item(TableName=table, Item={"pk": {"S": "row-1"}, "g1": {"S": "alpha"}})
    found = _poll_until(
        lambda: ddb.query(
            TableName=table,
            IndexName="gsi-main",
            KeyConditionExpression="g1 = :v",
            ExpressionAttributeValues={":v": {"S": "alpha"}},
        )["Items"],
        lambda items: items == [{"pk": {"S": "row-1"}, "g1": {"S": "alpha"}}],
        timeout_s=60.0,
        description="query through gsi-main returning the item it indexes",
    )
    assert found == [{"pk": {"S": "row-1"}, "g1": {"S": "alpha"}}], (
        f"expected the query through gsi-main to return the one item it indexes, got {found!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
