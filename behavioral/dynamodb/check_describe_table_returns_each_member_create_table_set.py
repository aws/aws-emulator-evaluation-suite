"""describe-table-returns-each-member-create-table-set."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-table-returns-each-member-create-table-set"
GROUP = "representation"
SERVICES = ["dynamodb"]



def _wait_cap(ctx, cap_s: float) -> float:
    """cap_s, shortened when the runner stops the check sooner, keeping 5 s for the failure."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _drop_table(ddb, name: str):
    """A cleanup deleting the table, backing off while a create or tag update holds it; a failure raises."""

    def status() -> str:
        try:
            return ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return "GONE"

    def undo() -> None:
        for attempt in range(8):
            # A table just created can still read not-found, so GONE still sends the delete.
            if status() == "DELETING":
                return
            try:
                ddb.delete_table(TableName=name)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException" or attempt == 7:
                    raise
            time.sleep(min(3 * 2 ** attempt, 60))

    return undo


def _new_table(ctx, ddb, name: str, **params) -> dict:
    """CreateTable, its delete registered at once, then DescribeTable polled to ACTIVE."""
    ddb.create_table(TableName=name, **params)
    ctx.on_cleanup(_drop_table(ddb, name))
    deadline = time.monotonic() + _wait_cap(ctx, 240.0)
    while True:
        try:
            table = ddb.describe_table(TableName=name)["Table"]
        except ClientError as exc:
            # DescribeTable can read not-found for a moment after CreateTable.
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or time.monotonic() >= deadline:
                raise
            table = {"TableStatus": "CREATING"}
        if table["TableStatus"] == "ACTIVE" or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert table["TableStatus"] == "ACTIVE", f"table {name} settled at {table['TableStatus']!r}"
    return table


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTable on the ACTIVE table returns each member CreateTable set with the value sent:
    keys, attribute types, on-demand billing, table class and stream.
    """
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-dtcm-")
    attributes = [{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "N"}]
    keys = [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}]
    stream = {"StreamEnabled": True, "StreamViewType": "KEYS_ONLY"}
    _new_table(
        ctx, ddb, name, AttributeDefinitions=attributes, KeySchema=keys, BillingMode="PAY_PER_REQUEST",
        TableClass="STANDARD_INFREQUENT_ACCESS", StreamSpecification=stream,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    table = ddb.describe_table(TableName=name)["Table"]
    sent = {
        "TableName": name,
        "AttributeDefinitions": sorted(attributes, key=lambda a: a["AttributeName"]),
        "KeySchema": keys,
        "BillingMode": "PAY_PER_REQUEST",
        "TableClass": "STANDARD_INFREQUENT_ACCESS",
        "StreamSpecification": stream,
    }
    read = {
        "TableName": table.get("TableName"),
        "AttributeDefinitions": sorted(table.get("AttributeDefinitions", []), key=lambda a: a["AttributeName"]),
        "KeySchema": table.get("KeySchema"),
        "BillingMode": table.get("BillingModeSummary", {}).get("BillingMode"),
        "TableClass": table.get("TableClassSummary", {}).get("TableClass"),
        "StreamSpecification": table.get("StreamSpecification"),
    }
    differ = {m: {"sent": sent[m], "read": read[m]} for m in sent if read[m] != sent[m]}
    assert differ == {}, f"DescribeTable does not return what CreateTable set: {differ!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
