"""update-table-decrease-after-increase-records-number-of-decreases-today."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-table-decrease-after-increase-records-number-of-decreases-today"
GROUP = "table_lifecycle"
SERVICES = ["dynamodb"]


def _poll_until(ddb, table: str, predicate, *, timeout_s: float, description: str) -> dict:
    """Poll DescribeTable every 2 s for ``table`` until ``predicate(table_desc)`` holds."""
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if predicate(desc):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} never reached {description}; last {desc!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A provisioned-capacity decrease that follows an increase leaves DescribeTable reporting
    NumberOfDecreasesToday 1 and LastDecreaseDateTime no earlier than LastIncreaseDateTime.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-incdec-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    active = _poll_until(
        ddb, table, lambda d: d["TableStatus"] == "ACTIVE", timeout_s=280, description="ACTIVE"
    )
    pt0 = active["ProvisionedThroughput"]
    assert pt0.get("NumberOfDecreasesToday") == 0, (
        f"a fresh table's ProvisionedThroughput is {pt0!r}, expected NumberOfDecreasesToday 0"
    )

    ddb.update_table(
        TableName=table, ProvisionedThroughput={"ReadCapacityUnits": 3, "WriteCapacityUnits": 3}
    )
    increased = _poll_until(
        ddb, table,
        lambda d: d["TableStatus"] == "ACTIVE"
        and (d["ProvisionedThroughput"].get("ReadCapacityUnits"),
             d["ProvisionedThroughput"].get("WriteCapacityUnits")) == (3, 3),
        timeout_s=280, description="ACTIVE at 3 read / 3 write",
    )["ProvisionedThroughput"]
    last_increase = increased.get("LastIncreaseDateTime")
    assert last_increase is not None, (
        f"ProvisionedThroughput after the increase is {increased!r}, expected LastIncreaseDateTime present"
    )
    assert "LastDecreaseDateTime" not in increased, (
        f"ProvisionedThroughput after only an increase is {increased!r}, expected LastDecreaseDateTime absent"
    )

    ddb.update_table(
        TableName=table, ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1}
    )
    decreased = _poll_until(
        ddb, table,
        lambda d: d["TableStatus"] == "ACTIVE"
        and (d["ProvisionedThroughput"].get("ReadCapacityUnits"),
             d["ProvisionedThroughput"].get("WriteCapacityUnits")) == (1, 1),
        timeout_s=280, description="ACTIVE at 1 read / 1 write",
    )["ProvisionedThroughput"]

    assert decreased.get("NumberOfDecreasesToday") == 1, (
        f"ProvisionedThroughput after one decrease is {decreased!r}, expected NumberOfDecreasesToday 1"
    )
    last_decrease = decreased.get("LastDecreaseDateTime")
    assert last_decrease is not None, (
        f"ProvisionedThroughput after the decrease is {decreased!r}, expected LastDecreaseDateTime present"
    )
    assert last_decrease >= last_increase, (
        f"LastDecreaseDateTime {last_decrease!r} is earlier than LastIncreaseDateTime {last_increase!r}"
    )
    assert decreased.get("LastIncreaseDateTime") == last_increase, (
        f"LastIncreaseDateTime changed from {last_increase!r} to {decreased.get('LastIncreaseDateTime')!r} "
        "across a call that only decreased capacity"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
