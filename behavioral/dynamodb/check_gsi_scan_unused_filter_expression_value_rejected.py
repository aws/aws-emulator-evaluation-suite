"""gsi-scan-unused-filter-expression-value-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-scan-unused-filter-expression-value-rejected"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_IDX = "by-tag"

#: id (S) hash key on the base table; tag (S) is the GSI's own hash key (never empty: a GSI key
#: attribute rejects the empty string).
_ITEMS = (
    {"id": {"S": "item1"}, "tag": {"S": "none"}, "resolvedAt": {"N": "1640995200"}},
    {"id": {"S": "item2"}, "tag": {"S": "none"}, "resolvedAt": {"N": "1672531200"}},
    {"id": {"S": "item3"}, "tag": {"S": "active"}, "resolvedAt": {"N": "0"}},
)
_FILTER = "tag = :none_tag AND resolvedAt > :zero"
_VALUES = {":none_tag": {"S": "none"}, ":zero": {"N": "0"}}
_MATCH = tuple(sorted(it["id"]["S"] for it in _ITEMS if it["tag"]["S"] == "none" and int(it["resolvedAt"]["N"]) > 0))


def _error(fn) -> tuple:
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll(fn, pred, *, timeout_s, interval_s=2.0, description="condition"):
    """Poll `fn` until `pred` holds: a GSI is eventually consistent, so this waits rather than
    sleeping a fixed amount."""
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last: {value!r}")
        time.sleep(interval_s)
        value = fn()
    return value


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan of a global secondary index with an ExpressionAttributeValue the FilterExpression
    never references is refused ValidationException naming the unused key, while a
    FilterExpression that uses every value is served from the index.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-gsiscanfx-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "id", "AttributeType": "S"},
            {"AttributeName": "tag", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {"IndexName": _IDX, "KeySchema": [{"AttributeName": "tag", "KeyType": "HASH"}],
             "Projection": {"ProjectionType": "ALL"}},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    resp = ddb.batch_write_item(
        RequestItems={table: [{"PutRequest": {"Item": item}} for item in _ITEMS]}
    )
    assert resp["UnprocessedItems"] == {}, (
        f"BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed while seeding"
    )

    # --- positive control: a FilterExpression using every value is served from the index, once
    # --- the write has propagated into it (a GSI is eventually consistent) ---
    good = _poll(
        lambda: ddb.scan(TableName=table, IndexName=_IDX, FilterExpression=_FILTER,
                         ExpressionAttributeValues=_VALUES),
        lambda r: r["Count"] == len(_MATCH), timeout_s=120,
        description=f"the {len(_MATCH)} matching item(s) propagating into {_IDX}",
    )
    good_ids = tuple(sorted(it["id"]["S"] for it in good["Items"]))
    assert good_ids == _MATCH, f"the control scan via {_IDX!r} returned {good_ids!r}, expected {_MATCH!r}"

    # --- an ExpressionAttributeValue the filter never references is refused ---
    code, message = _error(lambda: ddb.scan(
        TableName=table, IndexName=_IDX, FilterExpression=_FILTER,
        ExpressionAttributeValues={**_VALUES, ":unused": {"S": "x"}},
    ))
    assert code == "ValidationException", (
        f"the index scan with an unused value was refused {code!r} ({message!r}), expected ValidationException"
    )
    expected = "Value provided in ExpressionAttributeValues unused in expressions: keys: {:unused}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
