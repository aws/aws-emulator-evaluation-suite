"""vector-item-size-gate-counts-stored-number-bytes."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vector-item-size-gate-counts-stored-number-bytes"
GROUP = "vector"
SERVICES = ["dynamodb"]

_DIMS = 4096
_PAD_BYTES = 370 * 1024

_ITEM_TOO_LARGE = ("ValidationException", "Item size has exceeded the maximum allowed size")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_active(ctx, ddb, table, cap_s=240.0):
    left = ctx.time_left()
    deadline = time.monotonic() + (cap_s if left is None else max(1.0, min(cap_s, left - 5.0)))
    tbl = ddb.describe_table(TableName=table)["Table"]
    while True:
        tbl = ddb.describe_table(TableName=table)["Table"]
        indexes = tbl.get("VectorIndexes", [])
        if tbl["TableStatus"] == "ACTIVE" and all(v.get("IndexStatus") == "ACTIVE" for v in indexes):
            return tbl
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"table/vector index never became ACTIVE in time: status "
                f"{tbl['TableStatus']!r}, indexes "
                f"{[(v.get('IndexName'), v.get('IndexStatus')) for v in indexes]!r}"
            )
        time.sleep(2)


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "plane:data",
      "dp:api")
def run(ctx) -> None:
    """The 400 KB item-size limit is computed from the vector's actual stored numbers, not from
    the fixed 4-bytes-per-dimension rate the write-capacity meter uses for the same attribute.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbvecgate-")

    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        VectorIndexes=[{
            "IndexName": "idx",
            "VectorAttribute": {"AttributeName": "v"},
            "Dimensions": _DIMS,
            "DistanceFunction": "COSINE",
            "Projection": {"ProjectionType": "KEYS_ONLY"},
        }],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table)))
    _wait_active(ctx, ddb, table)

    # Positive control: padding that brings the item close to the 400 KB limit, plus a vector
    # of single-digit numbers, fits comfortably — and the write's billed vector bytes are tiny
    # relative to the item's real size, which is dominated by the padding.
    ok_item = {
        "pk": {"S": "ok"},
        "pad": {"S": "x" * _PAD_BYTES},
        "v": {"L": [{"N": "1"}] * _DIMS},
    }
    ok_out = ddb.put_item(TableName=table, Item=ok_item, ReturnConsumedCapacity="INDEXES")
    ok_vwb = ok_out["ConsumedCapacity"].get("VectorIndexes", {}).get("idx", {}).get(
        "VectorWriteRequestBytes")
    assert ok_vwb == 16389.0, (
        f"the positive control's billed VectorWriteRequestBytes was {ok_vwb!r}, expected "
        f"16389.0 — tiny next to the ~370 KB of padding in the same item"
    )

    # The same padding, and the same dimension count, but numbers with far more significant
    # digits: the real stored size grows enough to cross the 400 KB limit, even though the
    # dimension count — and so the billed vector bytes above — did not change.
    bad_item = {
        "pk": {"S": "bad"},
        "pad": {"S": "x" * _PAD_BYTES},
        "v": {"L": [{"N": "9" * 38}] * _DIMS},
    }
    expect_error(
        lambda: ddb.put_item(TableName=table, Item=bad_item),
        *_ITEM_TOO_LARGE,
    )

    # The positive control's item persisted; the refused one never did.
    read_ok = ddb.get_item(TableName=table, Key={"pk": {"S": "ok"}}, ConsistentRead=True)
    assert "Item" in read_ok and read_ok["Item"]["v"]["L"][0]["N"] == "1", (
        f"the positive control's item did not read back as written: {read_ok.get('Item')!r}"
    )
    read_bad = ddb.get_item(TableName=table, Key={"pk": {"S": "bad"}}, ConsistentRead=True)
    assert "Item" not in read_bad, (
        f"the refused PutItem left an item behind: {read_bad.get('Item')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
