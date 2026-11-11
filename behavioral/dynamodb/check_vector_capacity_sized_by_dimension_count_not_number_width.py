"""vector-capacity-sized-by-dimension-count-not-number-width."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vector-capacity-sized-by-dimension-count-not-number-width"
GROUP = "vector"
SERVICES = ["dynamodb"]

_LOW_DIMS = 254
_EDGE_DIMS = 255
_HIGH_DIMS = 4096


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _vi(name, attr, dims):
    return {
        "IndexName": name,
        "VectorAttribute": {"AttributeName": attr},
        "Dimensions": dims,
        "DistanceFunction": "COSINE",
        "Projection": {"ProjectionType": "KEYS_ONLY"},
    }


def _wait_active(ctx, ddb, table, n_indexes, cap_s=240.0):
    left = ctx.time_left()
    deadline = time.monotonic() + (cap_s if left is None else max(1.0, min(cap_s, left - 5.0)))
    tbl = ddb.describe_table(TableName=table)["Table"]
    while True:
        tbl = ddb.describe_table(TableName=table)["Table"]
        indexes = tbl.get("VectorIndexes", [])
        if (tbl["TableStatus"] == "ACTIVE" and len(indexes) == n_indexes
                and all(v.get("IndexStatus") == "ACTIVE" for v in indexes)):
            return tbl
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"table/vector indexes never became ACTIVE in time: status "
                f"{tbl['TableStatus']!r}, indexes "
                f"{[(v.get('IndexName'), v.get('IndexStatus')) for v in indexes]!r}"
            )
        time.sleep(2)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A vector index's write capacity scales at 4 bytes per dimension, floored at 1024 bytes,
    identically whatever digit width the stored numbers use; a strongly consistent GetItem's
    capacity tracks that same billed size rather than the numbers' real stored width.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbveccap-")

    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        VectorIndexes=[
            _vi("idx-low", "a", _LOW_DIMS),
            _vi("idx-edge", "b", _EDGE_DIMS),
            _vi("idx-big", "c", _HIGH_DIMS),
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table)))
    _wait_active(ctx, ddb, table, 3)

    def _put(key, attr, dims, digits):
        item = {"pk": {"S": key}, attr: {"L": [{"N": "9" * digits}] * dims}}
        out = ddb.put_item(TableName=table, Item=item, ReturnConsumedCapacity="INDEXES")
        return out["ConsumedCapacity"]

    # One dimension below the per-dimension threshold: the per-write floor of 1024 bytes applies,
    # and the table write costs exactly 1 WCU.
    low = _put("e1", "a", _LOW_DIMS, 1)
    low_bytes = low.get("VectorIndexes", {}).get("idx-low", {}).get("VectorWriteRequestBytes")
    assert low_bytes == 1024.0, (
        f"a {_LOW_DIMS}-dimension write's VectorWriteRequestBytes was {low_bytes!r}, "
        f"expected the 1024-byte floor"
    )
    assert low.get("Table", {}).get("CapacityUnits") == 1.0, (
        f"table WCU for the floored write was {low.get('Table')!r}, expected 1.0"
    )

    # One dimension more crosses the floor by exactly one byte, and the table WCU doubles at
    # that 1024/1025-byte boundary.
    edge_small = _put("e2", "b", _EDGE_DIMS, 1)
    edge_small_bytes = edge_small.get("VectorIndexes", {}).get("idx-edge", {}).get(
        "VectorWriteRequestBytes")
    assert edge_small_bytes == 1025.0, (
        f"a {_EDGE_DIMS}-dimension write's VectorWriteRequestBytes was {edge_small_bytes!r}, "
        f"expected 1025.0, one byte past the floor"
    )
    assert edge_small.get("Table", {}).get("CapacityUnits") == 2.0, (
        f"table WCU just past the floor was {edge_small.get('Table')!r}, expected 2.0"
    )

    # The same dimension count, same key, but numbers with far more significant digits: the
    # billed bytes do not move, because the per-dimension rate does not look at the numbers.
    edge_big = _put("e3", "b", _EDGE_DIMS, 38)
    edge_big_bytes = edge_big.get("VectorIndexes", {}).get("idx-edge", {}).get(
        "VectorWriteRequestBytes")
    assert edge_big_bytes == edge_small_bytes == 1025.0, (
        f"38-significant-digit numbers changed VectorWriteRequestBytes to {edge_big_bytes!r}, "
        f"expected the same 1025.0 as single-digit numbers at the same dimension count"
    )

    # At a much larger dimension count the same invariance holds, and establishes the billed
    # size that the read capacity below is compared against.
    big_small = _put("e4", "c", _HIGH_DIMS, 1)
    big_small_bytes = big_small.get("VectorIndexes", {}).get("idx-big", {}).get(
        "VectorWriteRequestBytes")
    assert big_small_bytes == 16389.0, (
        f"a {_HIGH_DIMS}-dimension write's VectorWriteRequestBytes was {big_small_bytes!r}, "
        f"expected 16389.0"
    )
    assert big_small.get("Table", {}).get("CapacityUnits") == 17.0, (
        f"table WCU for the {_HIGH_DIMS}-dimension write was {big_small.get('Table')!r}, "
        f"expected 17.0"
    )

    big_big = _put("e5", "c", _HIGH_DIMS, 38)
    big_big_bytes = big_big.get("VectorIndexes", {}).get("idx-big", {}).get(
        "VectorWriteRequestBytes")
    assert big_big_bytes == big_small_bytes == 16389.0, (
        f"38-significant-digit numbers at {_HIGH_DIMS} dimensions changed VectorWriteRequestBytes "
        f"to {big_big_bytes!r}, expected the same 16389.0 as single-digit numbers"
    )

    # A strongly consistent GetItem's capacity tracks that same billed size, not the numbers'
    # real stored width: the single-digit and the 38-digit item cost the same to read.
    read_small = ddb.get_item(TableName=table, Key={"pk": {"S": "e4"}}, ConsistentRead=True,
                              ReturnConsumedCapacity="TOTAL")
    read_big = ddb.get_item(TableName=table, Key={"pk": {"S": "e5"}}, ConsistentRead=True,
                            ReturnConsumedCapacity="TOTAL")
    read_small_cu = read_small.get("ConsumedCapacity", {}).get("CapacityUnits")
    read_big_cu = read_big.get("ConsumedCapacity", {}).get("CapacityUnits")
    assert read_small_cu == 5.0, (
        f"a consistent GetItem of the {_HIGH_DIMS}-dimension item cost {read_small_cu!r} RCU, "
        f"expected 5.0"
    )
    assert read_big_cu == read_small_cu == 5.0, (
        f"the 38-significant-digit item cost {read_big_cu!r} RCU to read, expected the same "
        f"5.0 as the single-digit item at the same dimension count"
    )
    assert read_small["Item"]["c"]["L"][0]["N"] == "9", (
        f"GetItem returned the single-digit item's first component as "
        f"{read_small['Item']['c']['L'][0]['N']!r}, expected '9'"
    )
    assert read_big["Item"]["c"]["L"][0]["N"] == "9" * 38, (
        f"GetItem returned the 38-digit item's first component as "
        f"{read_big['Item']['c']['L'][0]['N']!r}, expected 38 nines"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
