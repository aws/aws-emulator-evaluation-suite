"""transact-get-items-bills-missing-items-and-reports-indexes-capacity."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-get-items-bills-missing-items-and-reports-indexes-capacity"
GROUP = "transactions"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found, timeout_s=300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo():
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table and its indexes are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _create_table(ctx, ddb, prefix, range_type=None):
    """Create an on-demand table keyed pk (S), plus sk of range_type when given; wait ACTIVE."""
    table = ctx.unique_name(prefix)
    keys = [{"AttributeName": "pk", "KeyType": "HASH"}]
    attrs = [{"AttributeName": "pk", "AttributeType": "S"}]
    if range_type:
        keys.append({"AttributeName": "sk", "KeyType": "RANGE"})
        attrs.append({"AttributeName": "sk", "AttributeType": range_type})
    ddb.create_table(
        TableName=table, KeySchema=keys, AttributeDefinitions=attrs, BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    return table


def _capacity(resp, label):
    """The single ConsumedCapacity entry of a TransactGetItems response."""
    consumed = resp.get("ConsumedCapacity")
    assert isinstance(consumed, list) and len(consumed) == 1, f"{label}: ConsumedCapacity was {consumed!r}"
    return consumed[0]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TransactGetItems bills 2 read units per Get even when the item is missing, and INDEXES on a
    table without indexes reports read units for the table and no write units or index entries.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb, "sim2real-behav-ddb-txrcu-")
    present = {"pk": {"S": "present"}, "v": {"S": "small"}}
    ddb.put_item(TableName=table, Item=present)
    present_get = {"Get": {"TableName": table, "Key": {"pk": {"S": "present"}}}}
    missing_get = {"Get": {"TableName": table, "Key": {"pk": {"S": "missing"}}}}

    alone = ddb.transact_get_items(TransactItems=[missing_get], ReturnConsumedCapacity="TOTAL")
    assert alone["Responses"] == [{}], f"a Get of a missing key returned {alone['Responses']!r}"
    cap = _capacity(alone, "missing alone")
    got = (cap.get("TableName"), cap.get("CapacityUnits"), cap.get("ReadCapacityUnits"))
    assert got == (table, 2.0, 2.0), f"a Get of a missing key consumed {cap!r}, expected 2.0 read units"

    pair = ddb.transact_get_items(TransactItems=[present_get, missing_get], ReturnConsumedCapacity="TOTAL")
    assert pair["Responses"] == [{"Item": present}, {}], f"present+missing returned {pair['Responses']!r}"
    cap = _capacity(pair, "present+missing")
    got = (cap.get("TableName"), cap.get("CapacityUnits"), cap.get("ReadCapacityUnits"))
    assert got == (table, 4.0, 4.0), f"present+missing consumed {cap!r}, expected 4.0 read units"

    indexed = ddb.transact_get_items(TransactItems=[present_get], ReturnConsumedCapacity="INDEXES")
    assert indexed["Responses"] == [{"Item": present}], f"INDEXES Get returned {indexed['Responses']!r}"
    cap = _capacity(indexed, "INDEXES")
    got = (cap.get("TableName"), cap.get("CapacityUnits"), cap.get("ReadCapacityUnits"))
    assert got == (table, 2.0, 2.0), f"INDEXES consumed {cap!r}, expected 2.0 read units"
    assert "WriteCapacityUnits" not in cap, f"a transactional read reported write units: {cap!r}"
    assert cap.get("Table") == {"CapacityUnits": 2.0, "ReadCapacityUnits": 2.0}, (
        f"INDEXES Table breakdown was {cap.get('Table')!r}"
    )
    stray = sorted(k for k in ("GlobalSecondaryIndexes", "LocalSecondaryIndexes") if k in cap)
    assert stray == [], f"a table without indexes reported index capacity under {stray!r}: {cap!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
