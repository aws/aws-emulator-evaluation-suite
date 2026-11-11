"""ddb-eventual-and-strong-read-are-two-different-reads."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "ddb-eventual-and-strong-read-are-two-different-reads"

GROUP = "consistency"

SERVICES = ["dynamodb"]

# A DynamoDB item's billable size is the sum, over every attribute, of the UTF-8 length of the
# name plus the length of the value. WCU = ceil(size / 1024) and a strong RCU = ceil(size / 4096);
# an eventually consistent read of the same item is exactly half that. So the 2049..3072 band bills
# 3 WCU / 1.0 strong / 0.5 eventual RCU, and the 4097..5120 band bills 5 WCU / 2.0 / 1.0.
_BAND_3KB = 3 * 1024
_BAND_5KB = 5 * 1024

_PAIRS = 200
_GSI = "gk-index"


def _pad_for(band: int, pk: str) -> str:
    """Padding that lands the whole item just inside `band` bytes.

    Overhead accounted for: the "pk" name (2) + its value, the "pad" name (3), the "v" name (1)
    and the numeric value of v (<= 8 bytes of slack covers every value this check writes).
    """
    return "x" * (band - len(pk) - 2 - 3 - 1 - 8)


def _error(fn) -> tuple[str, str]:
    """The AWS (code, message) raised by fn(); raises if fn() unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(
        "the call was expected to be rejected by the service but it SUCCEEDED -- a target that "
        "accepts this input is more broken than one that returns the wrong error code"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s=0.5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Strong and eventual reads of one item bill 1.0/0.5 RCU up to 4 KB and 2.0/1.0 above; strong
    reads are never stale, eventual reads return some written value (canary 0 included) and never a
    newer one, and a GSI refuses ConsistentRead=True with an exact message.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadConsistency.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbcr-")

    # On-demand reports read units unrounded, so the 0.5 RCU of an eventual read is observable.
    ddb.create_table(
        TableName=table,
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "gk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": _GSI,
                "KeySchema": [{"AttributeName": "gk", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    items = {
        "small": {"band": _BAND_3KB, "wcu": 3.0, "strong": 1.0, "eventual": 0.5, "v": 0},
        "large": {"band": _BAND_5KB, "wcu": 5.0, "strong": 2.0, "eventual": 1.0, "v": 0},
    }
    for pk, spec in items.items():
        put = ddb.put_item(
            TableName=table,
            Item={
                "pk": {"S": pk},
                "pad": {"S": _pad_for(spec["band"], pk)},
                "v": {"N": "0"},
            },
            ReturnConsumedCapacity="TOTAL",
        )
        got = put["ConsumedCapacity"]["CapacityUnits"]
        assert got == spec["wcu"], (
            f"canary write of the {spec['band']}-byte {pk!r} item billed {got!r} WCU, expected "
            f"{spec['wcu']!r}. The RCU assertions below rest on this arithmetic, so a mismatch "
            f"here means the item is not the size this check believes it is -- fix the padding, do "
            f"not relax the read assertions."
        )

    stale_strong: list[tuple[int, str, object]] = []
    phantom_eventual: list[tuple[int, str, object]] = []
    future_eventual: list[tuple[int, str, object]] = []
    bad_capacity: list[tuple[int, str, str, float, float]] = []
    disagreements = 0

    for i in range(_PAIRS):
        pk = "small" if i % 2 == 0 else "large"
        spec = items[pk]
        spec["v"] += 1
        want = spec["v"]
        ddb.put_item(
            TableName=table,
            Item={
                "pk": {"S": pk},
                "pad": {"S": _pad_for(spec["band"], pk)},
                "v": {"N": str(want)},
            },
        )

        def _read(consistent: bool):
            resp = ddb.get_item(
                TableName=table,
                Key={"pk": {"S": pk}},
                ConsistentRead=consistent,
                ReturnConsumedCapacity="TOTAL",
            )
            value = resp["Item"]["v"]["N"] if "Item" in resp else None
            return value, resp["ConsumedCapacity"]["CapacityUnits"]

        # Alternate which read goes first so neither mode is systematically advantaged.
        if i % 4 < 2:
            strong_v, strong_cu = _read(True)
            eventual_v, eventual_cu = _read(False)
        else:
            eventual_v, eventual_cu = _read(False)
            strong_v, strong_cu = _read(True)

        if strong_v != str(want):
            stale_strong.append((i, pk, strong_v))
        # Every value 0..want was written to this key (0 is the canary), so any of them is lag.
        if eventual_v is None or not str(eventual_v).isdigit():
            phantom_eventual.append((i, pk, eventual_v))
        elif int(eventual_v) > want:
            future_eventual.append((i, pk, eventual_v))
        if strong_cu != spec["strong"]:
            bad_capacity.append((i, pk, "strong", strong_cu, spec["strong"]))
        if eventual_cu != spec["eventual"]:
            bad_capacity.append((i, pk, "eventual", eventual_cu, spec["eventual"]))
        if strong_v != eventual_v:
            disagreements += 1

    assert not stale_strong, (
        f"{len(stale_strong)} of {_PAIRS} ConsistentRead=True reads were STALE -- a strong read "
        f"issued after a completed PutItem must never miss it. First offenders "
        f"(iteration, item, value returned): {stale_strong[:5]!r}"
    )
    assert not phantom_eventual, (
        f"{len(phantom_eventual)} of {_PAIRS} ConsistentRead=False reads returned a value that was "
        f"never written (or no item at all). Lag is permitted; invention is not. First offenders: "
        f"{phantom_eventual[:5]!r}"
    )
    assert not future_eventual, (
        f"{len(future_eventual)} of {_PAIRS} ConsistentRead=False reads returned a value NEWER than "
        f"the write that preceded them -- an eventual read may lag the leader, never lead it. "
        f"First offenders: {future_eventual[:5]!r}"
    )

    assert not bad_capacity, (
        f"{len(bad_capacity)} of {2 * _PAIRS} reads billed the wrong capacity. A strong read of a "
        f"<=4 KB item costs 1.0 RCU and the eventual read of the same item costs exactly half, "
        f"0.5; across the 4 KB boundary both double to 2.0 and 1.0. An emulator that keeps one "
        f"copy of the data has no second read path to bill differently. First offenders "
        f"(iteration, item, mode, got, expected): {bad_capacity[:6]!r}"
    )
    assert disagreements < _PAIRS, (
        f"every one of the {_PAIRS} eventual reads disagreed with the strong read taken in the "
        f"same iteration. Lag is expected; being wrong 200/200 means the eventual read is not "
        f"tracking the table at all."
    )

    # A GetItem miss still consumes read capacity at the same 2:1 ratio.
    for consistent, want_cu in ((True, 1.0), (False, 0.5)):
        miss = ddb.get_item(
            TableName=table,
            Key={"pk": {"S": "never-written-key"}},
            ConsistentRead=consistent,
            ReturnConsumedCapacity="TOTAL",
        )
        assert "Item" not in miss, (
            f"GetItem(ConsistentRead={consistent}) on a key that was never written returned an "
            f"item: {miss.get('Item')!r}"
        )
        got_cu = miss["ConsumedCapacity"]["CapacityUnits"]
        assert got_cu == want_cu, (
            f"GetItem(ConsistentRead={consistent}) on an ABSENT key billed {got_cu!r}, expected "
            f"{want_cu!r}. A read that finds nothing is still a read, and the eventual/strong "
            f"price ratio is the same 1:2 as for a hit -- an emulator that bills 0 for a miss has "
            f"no capacity model."
        )

    base_q = {
        "TableName": table,
        "KeyConditionExpression": "pk = :p",
        "ExpressionAttributeValues": {":p": {"S": "small"}},
        "ReturnConsumedCapacity": "TOTAL",
    }
    strong_q = ddb.query(ConsistentRead=True, **base_q)
    eventual_q = ddb.query(ConsistentRead=False, **base_q)
    assert strong_q["Count"] == 1 and eventual_q["Count"] == 1, (
        f"the base-table Query returned Count {strong_q['Count']!r} strong / "
        f"{eventual_q['Count']!r} eventual, expected 1 and 1"
    )
    sq = strong_q["ConsumedCapacity"]["CapacityUnits"]
    eq = eventual_q["ConsumedCapacity"]["CapacityUnits"]
    assert (sq, eq) == (1.0, 0.5), (
        f"a base-table Query billed {sq!r} strong / {eq!r} eventual, expected 1.0 / 0.5. Query on "
        f"the table itself DOES support a strong read -- the 2:1 ratio is a property of the read "
        f"mode, not of GetItem."
    )

    # A GSI is projected asynchronously, so poll until the item is in it before asserting.
    ddb.put_item(TableName=table, Item={"pk": {"S": "indexed"}, "gk": {"S": "g1"}})

    def _gsi_query(**extra):
        return ddb.query(
            TableName=table,
            IndexName=_GSI,
            KeyConditionExpression="gk = :g",
            ExpressionAttributeValues={":g": {"S": "g1"}},
            ReturnConsumedCapacity="TOTAL",
            **extra,
        )

    before = _poll_until(
        _gsi_query,
        lambda r: r["Count"] == 1,
        timeout_s=30.0,
        description=(
            "the GSI projecting the item written to the base table (AWS documents GSI updates as "
            "'usually propagated within a fraction of a second'; 30s is ~100x that, so a timeout "
            "here means broken rather than slow)"
        ),
    )
    assert before["ScannedCount"] >= 1, (
        f"the GSI query scanned {before['ScannedCount']!r} entries -- the index-empty assertions "
        f"below would be vacuous if the index were never actually read"
    )

    code, message = _error(lambda: _gsi_query(ConsistentRead=True))
    assert code == "ValidationException", (
        f"Query(IndexName={_GSI!r}, ConsistentRead=True) was rejected with {code!r}, expected "
        f"'ValidationException'. There is no strongly-consistent read of a global secondary index, "
        f"so there is no capacity price for one either."
    )
    expected_message = "Consistent reads are not supported on global secondary indexes"
    assert message == expected_message, (
        f"the GSI refusal message was {message!r}, expected {expected_message!r}: a caller has to be "
        f"able to tell 'this index cannot be read strongly' from 'this index does not exist'"
    )

    after = _gsi_query()
    assert after["Count"] == before["Count"] == 1 and after["Items"] == before["Items"], (
        f"the REFUSED ConsistentRead query changed what the GSI returns: before "
        f"{before['Items']!r}, after {after['Items']!r}. A rejected read must have no effect."
    )

    control_cu = after["ConsumedCapacity"]["CapacityUnits"]
    assert control_cu == 0.5, (
        f"the same GSI Query with ConsistentRead omitted billed {control_cu!r}, expected 0.5. A GSI "
        f"read is ALWAYS billed at the eventually-consistent rate; an emulator reporting 1.0 is "
        f"charging for a read path that does not exist."
    )

    # ConsistentRead is valid on the base table; the refusal above is about the index.
    on_table = ddb.query(ConsistentRead=True, **base_q)
    assert on_table["Count"] == 1, (
        f"ConsistentRead=True on the base table of the same table returned Count "
        f"{on_table['Count']!r}, expected 1. Without this control the ValidationException above "
        f"could mean 'this target does not support ConsistentRead at all'."
    )

    # The 'small'/'large' items carry no gk attribute, so the sparse index must never surface them.
    assert [it["pk"]["S"] for it in after["Items"]] == ["indexed"], (
        f"the sparse GSI returned {[it['pk']['S'] for it in after['Items']]!r}; only the item "
        f"carrying a 'gk' attribute belongs in it. An emulator that answers index queries out of "
        f"the base table returns the 400 items written above too."
    )


def _delete_table(ddb, table: str) -> None:
    """Delete the table and confirm it is gone rather than merely requested."""
    ddb.delete_table(TableName=table)
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        try:
            ddb.describe_table(TableName=table)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
