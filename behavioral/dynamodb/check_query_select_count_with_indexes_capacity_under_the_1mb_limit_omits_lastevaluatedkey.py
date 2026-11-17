"""query-select-count-with-indexes-capacity-under-the-1mb-limit-omits-lastevaluatedkey."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-select-count-with-indexes-capacity-under-the-1mb-limit-omits-lastevaluatedkey"
GROUP = "capacity"
SERVICES = ["dynamodb"]

_ITEM_PAYLOAD = 100_000
_ITEM_COUNT = 4
_ONE_MB = 1024 * 1024


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GSI Query under the 1 MB page limit returns no LastEvaluatedKey, and Select=COUNT with
    ReturnConsumedCapacity=INDEXES reports the same Count and index CapacityUnits as a full read.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddb-qcix-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gpk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "gsi1",
            "KeySchema": [{"AttributeName": "gpk", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=t), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    payload = "x" * _ITEM_PAYLOAD
    sks = [f"{i:03d}" for i in range(_ITEM_COUNT)]
    for sk in sks:
        ddb.put_item(
            TableName=t,
            Item={"pk": {"S": "p"}, "sk": {"S": sk}, "gpk": {"S": "g"}, "payload": {"S": payload}},
        )
    assert _ITEM_COUNT * _ITEM_PAYLOAD < _ONE_MB, (
        "the partition must stay comfortably under 1 MB so the limit never truncates it"
    )

    kwargs = dict(
        TableName=t,
        IndexName="gsi1",
        KeyConditionExpression="gpk = :g",
        ExpressionAttributeValues={":g": {"S": "g"}},
        ReturnConsumedCapacity="INDEXES",
    )
    # The GSI is eventually consistent: poll until it has caught up with every put above.
    deadline = time.monotonic() + 60
    baseline = ddb.query(**kwargs)
    while baseline["Count"] < _ITEM_COUNT and time.monotonic() < deadline:
        time.sleep(1)
        baseline = ddb.query(**kwargs)
    assert "LastEvaluatedKey" not in baseline, (
        f"a {_ITEM_COUNT}-item partition under 1 MB must return every item in one page with no "
        f"LastEvaluatedKey, got {baseline.get('LastEvaluatedKey')!r}"
    )
    assert baseline["Count"] == baseline["ScannedCount"] == _ITEM_COUNT, (
        f"expected Count == ScannedCount == {_ITEM_COUNT}, got Count={baseline['Count']!r} "
        f"ScannedCount={baseline['ScannedCount']!r}"
    )
    base_cc = baseline["ConsumedCapacity"]
    assert base_cc.get("Table", {}).get("CapacityUnits", 0) == 0, (
        f"a GSI query must charge the base table nothing, got {base_cc.get('Table')!r}"
    )
    gsi_units = base_cc["GlobalSecondaryIndexes"]["gsi1"]["CapacityUnits"]
    assert gsi_units > 0, f"the gsi1 arm must be charged, got {gsi_units!r}"

    counted = ddb.query(**kwargs, Select="COUNT")
    assert not counted.get("Items"), f"Select=COUNT must return no Items, got {counted.get('Items')!r}"
    assert "LastEvaluatedKey" not in counted, (
        f"Select=COUNT over the same under-the-limit partition must also omit "
        f"LastEvaluatedKey, got {counted.get('LastEvaluatedKey')!r}"
    )
    assert counted["Count"] == baseline["Count"], (
        f"Select=COUNT Count {counted['Count']!r} must equal the full read's Count "
        f"{baseline['Count']!r}"
    )
    assert counted["ScannedCount"] == baseline["ScannedCount"], (
        f"Select=COUNT ScannedCount {counted['ScannedCount']!r} must equal the full read's "
        f"ScannedCount {baseline['ScannedCount']!r}"
    )
    counted_cc = counted["ConsumedCapacity"]
    assert counted_cc.get("Table", {}).get("CapacityUnits", 0) == 0, (
        f"Select=COUNT on a GSI query must still charge the base table nothing, got "
        f"{counted_cc.get('Table')!r}"
    )
    counted_gsi_units = counted_cc["GlobalSecondaryIndexes"]["gsi1"]["CapacityUnits"]
    assert counted_gsi_units == gsi_units, (
        f"Select=COUNT billed the gsi1 arm {counted_gsi_units!r} CapacityUnits, the full read "
        f"billed {gsi_units!r} -- INDEXES capacity must price the bytes scanned, independent of "
        f"Select"
    )

    # Positive control: the base table itself still holds every item written, read back whole.
    got = ddb.get_item(TableName=t, Key={"pk": {"S": "p"}, "sk": {"S": sks[0]}}, ConsistentRead=True)
    assert got["Item"]["gpk"] == {"S": "g"}, f"expected gpk 'g' on the base item, got {got['Item'].get('gpk')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
