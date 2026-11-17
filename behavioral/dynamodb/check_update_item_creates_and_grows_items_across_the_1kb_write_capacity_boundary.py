"""update-item-creates-and-grows-items-across-the-1kb-write-capacity-boundary."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-creates-and-grows-items-across-the-1kb-write-capacity-boundary"
GROUP = "capacity"
SERVICES = ["dynamodb"]

# "pk" (2) + a 3-char key value (3) = 5 bytes of key overhead on every item below.
_KEY_BYTES = 5

# Binary attribute value bytes are billed 1:1 (no base64 expansion): "v" (1) + raw_len bytes.
# total 1024 -> 1 write unit, total 1025 -> 2 write units.
_B_LO = 1024 - _KEY_BYTES - 1  # 1018 raw bytes
_B_HI = _B_LO + 1              # 1019 raw bytes


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; the resource's own not-found
    code means it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_active(ddb, table: str, deadline: float) -> None:
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE with its GSI before the deadline: {desc!r}")


def _create_wcu(ddb, table: str, pk: str, attr: str, value: dict, return_cap: str) -> dict:
    """UpdateItem that creates a brand-new item with one attribute; the ConsumedCapacity dict."""
    resp = ddb.update_item(
        TableName=table, Key={"pk": {"S": pk}},
        UpdateExpression=f"SET {attr} = :v", ExpressionAttributeValues={":v": value},
        ReturnConsumedCapacity=return_cap,
    )
    return resp["ConsumedCapacity"]


def _bisect_new_item_boundary(ddb, table: str, pk_source, attr: str, value_for) -> tuple[int, int]:
    """(lo, hi) adjacent sizes where creating a brand-new item via UpdateItem bills 1.0 / 2.0 WCU."""

    def wcu(n: int) -> float:
        cc = _create_wcu(ddb, table, next(pk_source), attr, value_for(n), "TOTAL")
        return cc["CapacityUnits"]

    lo, hi = 1, 1024
    assert wcu(lo) == 1.0, f"a {lo}-byte {attr!r} value on a new item cost more than 1.0 WCU"
    while wcu(hi) < 2.0:
        hi *= 2
        assert hi < (1 << 20), "boundary search ran away without finding a 2.0 WCU item"
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if wcu(mid) < 2.0:
            lo = mid
        else:
            hi = mid
    assert wcu(lo) == 1.0, f"re-measurement at {lo} bytes no longer costs 1.0 WCU"
    assert wcu(hi) == 2.0, f"re-measurement at {hi} bytes no longer costs 2.0 WCU"
    return lo, hi


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem creating a brand-new item bills 1 WCU at exactly 1KB and 2 WCU one byte over,
    with TOTAL and untouched-index INDEXES shapes, and growing an existing item one byte past
    that edge bills on the larger post-update image.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/CapacityUnitCalculations.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbwcu-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "gpk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "gsi1",
            "KeySchema": [{"AttributeName": "gpk", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "KEYS_ONLY"},
        }],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 600.0) - 60.0)
    _wait_active(ddb, table, deadline)

    pk_source = iter(f"n{i:02d}" for i in range(1, 100))

    # --- a new item at exactly 1KB: TOTAL shape is the aggregate only ---
    cc_total = _create_wcu(ddb, table, next(pk_source), "v", {"B": b"x" * _B_LO}, "TOTAL")
    assert cc_total["CapacityUnits"] == 1.0, (
        f"a new {_KEY_BYTES + 1 + _B_LO}-byte item (TOTAL) cost {cc_total['CapacityUnits']!r} WCU, expected 1.0"
    )
    assert set(cc_total) == {"CapacityUnits", "TableName"}, (
        f"TOTAL ConsumedCapacity carried {sorted(cc_total)!r}, expected only CapacityUnits and TableName"
    )
    assert cc_total["TableName"] == table, f"TOTAL ConsumedCapacity named table {cc_total['TableName']!r}"

    # --- the same 1KB item, this time itemized: Table arm only, no GSI arm since gpk is untouched ---
    pk_idx = next(pk_source)
    cc_idx = _create_wcu(ddb, table, pk_idx, "v", {"B": b"x" * _B_LO}, "INDEXES")
    assert cc_idx["CapacityUnits"] == 1.0, f"a new 1KB item (INDEXES) cost {cc_idx['CapacityUnits']!r} WCU, expected 1.0"
    assert set(cc_idx) == {"CapacityUnits", "TableName", "Table"}, (
        f"INDEXES ConsumedCapacity for an item that never touches gpk carried {sorted(cc_idx)!r}, "
        f"expected CapacityUnits, TableName and Table only (no GlobalSecondaryIndexes arm)"
    )
    assert cc_idx["Table"] == {"CapacityUnits": 1.0}, f"Table arm was {cc_idx['Table']!r}, expected CapacityUnits 1.0"
    stored_idx = ddb.get_item(TableName=table, Key={"pk": {"S": pk_idx}}, ConsistentRead=True)["Item"]
    assert len(stored_idx["v"]["B"]) == _B_LO, f"the 1KB item read back {len(stored_idx['v']['B'])} raw bytes"

    # --- one byte over 1KB: a new item costs 2 WCU ---
    pk_over = next(pk_source)
    cc_over = _create_wcu(ddb, table, pk_over, "v", {"B": b"x" * _B_HI}, "TOTAL")
    assert cc_over["CapacityUnits"] == 2.0, (
        f"a new {_KEY_BYTES + 1 + _B_HI}-byte item cost {cc_over['CapacityUnits']!r} WCU, expected 2.0"
    )
    stored_over = ddb.get_item(TableName=table, Key={"pk": {"S": pk_over}}, ConsistentRead=True)["Item"]
    assert len(stored_over["v"]["B"]) == _B_HI, f"the 1025-byte item read back {len(stored_over['v']['B'])} raw bytes"

    # --- a Binary Set's own byte contribution: bisect it the same way as the plain Binary above ---
    bs_lo, bs_hi = _bisect_new_item_boundary(ddb, table, pk_source, "w", lambda n: {"BS": [b"y" * n]})
    assert bs_hi == bs_lo + 1, f"the BS boundary did not converge to adjacent raw lengths: {(bs_lo, bs_hi)!r}"
    bs_overhead = 1024 - _KEY_BYTES - 1 - bs_lo
    assert bs_overhead == 0, (
        f"a one-element Binary Set added {bs_overhead} byte(s) of overhead beyond its element's "
        f"raw length, expected 0"
    )

    # --- growing an existing item: staying at exactly 1KB still bills 1 WCU ---
    grow_pk = next(pk_source)
    ddb.put_item(TableName=table, Item={"pk": {"S": grow_pk}, "v": {"B": b"x" * 10}})
    grow_to_lo = ddb.update_item(
        TableName=table, Key={"pk": {"S": grow_pk}},
        UpdateExpression="SET v = :v", ExpressionAttributeValues={":v": {"B": b"x" * _B_LO}},
        ReturnConsumedCapacity="TOTAL",
    )["ConsumedCapacity"]
    assert grow_to_lo["CapacityUnits"] == 1.0, (
        f"growing a 15-byte item up to exactly 1KB (no crossing) cost {grow_to_lo['CapacityUnits']!r} "
        f"WCU, expected 1.0"
    )
    after_lo = ddb.get_item(TableName=table, Key={"pk": {"S": grow_pk}}, ConsistentRead=True)["Item"]
    assert len(after_lo["v"]["B"]) == _B_LO, f"the grown item read back {len(after_lo['v']['B'])} raw bytes"

    # --- growing it one byte further, crossing 1KB, bills on the larger post-update image ---
    grow_to_hi = ddb.update_item(
        TableName=table, Key={"pk": {"S": grow_pk}},
        UpdateExpression="SET v = :v", ExpressionAttributeValues={":v": {"B": b"x" * _B_HI}},
        ReturnConsumedCapacity="TOTAL",
    )["ConsumedCapacity"]
    assert grow_to_hi["CapacityUnits"] == 2.0, (
        f"growing a 1KB item one byte past the edge cost {grow_to_hi['CapacityUnits']!r} WCU, "
        f"expected 2.0 (the larger, post-update image)"
    )
    after_hi = ddb.get_item(TableName=table, Key={"pk": {"S": grow_pk}}, ConsistentRead=True)["Item"]
    assert len(after_hi["v"]["B"]) == _B_HI, f"the grown item read back {len(after_hi['v']['B'])} raw bytes"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
