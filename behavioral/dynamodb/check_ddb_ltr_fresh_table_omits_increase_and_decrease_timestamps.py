"""ddb-ltr-fresh-table-omits-increase-and-decrease-timestamps."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ddb-ltr-fresh-table-omits-increase-and-decrease-timestamps"
GROUP = "table-inventory-representation"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A fresh PROVISIONED table omits LastIncreaseDateTime and LastDecreaseDateTime; after an
    UpdateTable increase, LastIncreaseDateTime appears no earlier than the table's own
    CreationDateTime while LastDecreaseDateTime stays absent.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_DescribeTable.html
    """
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddb-ltr-incdec-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    table = _poll_table(ddb, name, lambda t: t["TableStatus"] == "ACTIVE", "ACTIVE")
    created = table["CreationDateTime"]
    pt = table["ProvisionedThroughput"]
    assert "LastIncreaseDateTime" not in pt and "LastDecreaseDateTime" not in pt, (
        f"a fresh table's ProvisionedThroughput is {pt!r}, expected neither timestamp present"
    )

    ddb.update_table(TableName=name, ProvisionedThroughput={"ReadCapacityUnits": 10, "WriteCapacityUnits": 10})
    # UpdateTable can return before DescribeTable leaves ACTIVE, so wait for the new capacities.
    pt2 = _poll_table(
        ddb, name,
        lambda t: t["TableStatus"] == "ACTIVE"
        and (t["ProvisionedThroughput"].get("ReadCapacityUnits"),
             t["ProvisionedThroughput"].get("WriteCapacityUnits")) == (10, 10),
        "ACTIVE at 10 read / 10 write",
    )["ProvisionedThroughput"]

    assert (pt2.get("ReadCapacityUnits"), pt2.get("WriteCapacityUnits")) == (10, 10), (
        f"ProvisionedThroughput after the increase is {pt2!r}, expected 10 read / 10 write"
    )
    increased = pt2.get("LastIncreaseDateTime")
    assert increased is not None, (
        f"ProvisionedThroughput after an increase is {pt2!r}, expected LastIncreaseDateTime present"
    )
    assert increased >= created, (
        f"LastIncreaseDateTime {increased!r} is earlier than the table's CreationDateTime {created!r}"
    )
    assert "LastDecreaseDateTime" not in pt2, (
        f"ProvisionedThroughput after only an increase is {pt2!r}, expected LastDecreaseDateTime absent"
    )


def _poll_table(ddb, name: str, done, description: str) -> dict:
    """Poll DescribeTable until ``done(table)`` holds, against a clock deadline."""
    deadline = time.monotonic() + 280
    t = None
    while time.monotonic() < deadline:
        t = ddb.describe_table(TableName=name)["Table"]
        if done(t):
            return t
        time.sleep(2)
    raise AssertionError(f"table {name} never reached {description}; last {t!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
