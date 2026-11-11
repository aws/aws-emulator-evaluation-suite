"""write-capacity-per-gsi-counts-index-inserts-removals-and-projected-size."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "write-capacity-per-gsi-counts-index-inserts-removals-and-projected-size"
GROUP = "capacity"
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
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 900.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _gsi(name, attr, projection):
    return {
        "IndexName": name,
        "KeySchema": [{"AttributeName": attr, "KeyType": "HASH"}],
        "Projection": {"ProjectionType": projection},
    }


def _breakdown(resp):
    """(total, table, {gsi: units}) of an INDEXES ConsumedCapacity."""
    cc = resp.get("ConsumedCapacity", {})
    gsis = {n: v.get("CapacityUnits") for n, v in cc.get("GlobalSecondaryIndexes", {}).items()}
    return cc.get("CapacityUnits"), cc.get("Table", {}).get("CapacityUnits"), gsis


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Write capacity counts one unit per GSI entry written or removed, sized by its projection; TOTAL
    sums base and indexes without a breakdown, and a write touching no projected attribute bills none.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GSI.html#GSI.ThroughputConsiderations.Writes
    """
    ddb = ctx.client("dynamodb")
    two = ctx.unique_name("sim2real-behav-ddb-gsicu-")
    ko = f"{two}-ko"
    ddb.create_table(
        TableName=two,
        AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ("pk", "g1", "g2")],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[_gsi("gsi1", "g1", "ALL"), _gsi("gsi2", "g2", "ALL")],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=two), "ResourceNotFoundException"))
    ddb.create_table(
        TableName=ko,
        AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ("pk", "g1")],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[_gsi("gsi_pk", "pk", "KEYS_ONLY"), _gsi("gsi_ko", "g1", "KEYS_ONLY")],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=ko), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, two)
    _wait_active(ddb, ctx, ko)

    both = {"g1": {"S": "x"}, "g2": {"S": "y"}}
    resp = ddb.put_item(TableName=two, Item={"pk": {"S": "c"}, **both}, ReturnConsumedCapacity="TOTAL")
    cc = resp.get("ConsumedCapacity", {})
    assert cc.get("CapacityUnits") == 3.0, f"TOTAL for a write into both GSIs is {cc!r}, expected 3.0"
    assert "Table" not in cc and "GlobalSecondaryIndexes" not in cc, f"TOTAL carries a breakdown: {cc!r}"

    resp = ddb.update_item(
        TableName=two, Key={"pk": {"S": "e"}}, UpdateExpression="SET g1 = :a, g2 = :b",
        ExpressionAttributeValues={":a": {"S": "x"}, ":b": {"S": "y"}}, ReturnConsumedCapacity="INDEXES",
    )
    got = _breakdown(resp)
    assert got == (3.0, 1.0, {"gsi1": 1.0, "gsi2": 1.0}), f"UpdateItem setting both GSI keys billed {got!r}"

    ddb.put_item(TableName=two, Item={"pk": {"S": "ow"}, **both})
    resp = ddb.put_item(TableName=two, Item={"pk": {"S": "ow"}, "g1": {"S": "x"}}, ReturnConsumedCapacity="INDEXES")
    got = _breakdown(resp)
    assert got == (3.0, 1.0, {"gsi1": 1.0, "gsi2": 1.0}), f"an overwrite dropping g2 billed {got!r}"

    ddb.put_item(TableName=two, Item={"pk": {"S": "rm"}, **both})
    resp = ddb.update_item(TableName=two, Key={"pk": {"S": "rm"}}, UpdateExpression="REMOVE g2",
                           ReturnConsumedCapacity="INDEXES")
    total, base, gsis = _breakdown(resp)
    assert (total, base, gsis) == (3.0, 1.0, {"gsi1": 1.0, "gsi2": 1.0}), (
        f"REMOVE g2 billed total {total!r}, table {base!r}, GSIs {gsis!r}"
    )
    assert total == base + sum(gsis.values()), f"REMOVE g2 billed total {total!r} for table {base!r} + {gsis!r}"

    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 120.0) - 20.0)

    def in_gsi2():
        return sorted(i["pk"]["S"] for p in ddb.get_paginator("scan").paginate(TableName=two, IndexName="gsi2")
                      for i in p["Items"])
    while True:
        held = in_gsi2()
        if held == ["c", "e"] or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert held == ["c", "e"], f"gsi2 holds {held!r}; the items whose g2 was dropped must have left it"

    resp = ddb.update_item(
        TableName=ko, Key={"pk": {"S": "up"}}, UpdateExpression="SET #o = :v",
        ExpressionAttributeNames={"#o": "other"}, ExpressionAttributeValues={":v": {"S": "created"}},
        ReturnConsumedCapacity="INDEXES",
    )
    got = _breakdown(resp)
    assert got == (2.0, 1.0, {"gsi_pk": 1.0}), f"an upsert on a table whose GSI reuses the base key billed {got!r}"

    resp = ddb.put_item(
        TableName=ko, Item={"pk": {"S": "a"}, "g1": {"S": "gv"}, "big": {"S": "x" * 2000}},
        ReturnConsumedCapacity="INDEXES",
    )
    got = _breakdown(resp)
    assert got == (4.0, 2.0, {"gsi_pk": 1.0, "gsi_ko": 1.0}), f"a 2 KB item into two KEYS_ONLY GSIs billed {got!r}"

    resp = ddb.update_item(
        TableName=ko, Key={"pk": {"S": "a"}}, UpdateExpression="SET big = :v",
        ExpressionAttributeValues={":v": {"S": "y" * 2000}}, ReturnConsumedCapacity="INDEXES",
    )
    got = _breakdown(resp)
    assert got == (2.0, 2.0, {}), f"an update of a non-projected attribute billed {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
