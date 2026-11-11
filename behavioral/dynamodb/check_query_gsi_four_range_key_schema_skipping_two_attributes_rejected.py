"""query-gsi-four-range-key-schema-skipping-two-attributes-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-gsi-four-range-key-schema-skipping-two-attributes-rejected"
GROUP = "gsi"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"
_INDEX = "by-four-range"
_RANGE = ["gsk1", "gsk2", "gsk3", "gsk4"]


def _error(fn) -> tuple:
    """The (code, message) ``fn`` is refused with. An unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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


def _poll(ctx, read, want):
    """read() every 2 s until it equals want, bounded by the run budget."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 120.0) - 20.0)
    while True:
        value = read()
        if value == want or time.monotonic() >= deadline:
            return value
        time.sleep(2)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GSI keyed on one HASH and four RANGE attributes requires an equality condition on every
    RANGE attribute before the last one referenced; skipping several at once is ValidationException
    naming every skipped attribute, while the full equality prefix still returns the item.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-gsi4rx-")
    key_schema = [{"AttributeName": "gpk", "KeyType": "HASH"}] + [
        {"AttributeName": n, "KeyType": "RANGE"} for n in _RANGE
    ]
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ["pk", "gpk", *_RANGE]],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": key_schema,
            "Projection": {"ProjectionType": "ALL"},
        }],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    desc = _wait_active(ddb, ctx, table)
    described = desc["GlobalSecondaryIndexes"][0]["KeySchema"]
    assert described == key_schema, f"the GSI describes its key as {described!r}"

    ddb.put_item(TableName=table, Item={
        "pk": {"S": "p1"}, "gpk": {"S": "g1"},
        "gsk1": {"S": "a"}, "gsk2": {"S": "b"}, "gsk3": {"S": "c"}, "gsk4": {"S": "d"},
    })

    def query(**kwargs):
        return ddb.query(TableName=table, IndexName=_INDEX, **kwargs)

    def pks(**cond) -> list:
        items = []
        for page in ddb.get_paginator("query").paginate(TableName=table, IndexName=_INDEX, **cond):
            items.extend(page["Items"])
        return sorted(i["pk"]["S"] for i in items)

    # Conditioning on gsk1 and gsk4 while skipping both gsk2 and gsk3 (in between) names every
    # attribute that must have an equality condition before gsk4 can carry one.
    code, message = _error(lambda: query(
        KeyConditionExpression="gpk = :g AND gsk1 = :v1 AND gsk4 = :v4",
        ExpressionAttributeValues={":g": {"S": "g1"}, ":v1": {"S": "a"}, ":v4": {"S": "d"}},
    ))
    assert code == ERR_VALIDATION, f"skipping gsk2 and gsk3 gave {code!r}"
    expected = (
        "RANGE key attributes gsk2, gsk3 must have equality conditions specified in the query "
        "because a condition is present on key attribute gsk4"
    )
    assert message == expected, f"skipping gsk2 and gsk3: expected {expected!r}, got {message!r}"

    # Conditioning only on gsk4, with no condition at all on gsk1, gsk2 or gsk3, names all three.
    code, message = _error(lambda: query(
        KeyConditionExpression="gpk = :g AND gsk4 = :v4",
        ExpressionAttributeValues={":g": {"S": "g1"}, ":v4": {"S": "d"}},
    ))
    assert code == ERR_VALIDATION, f"conditioning only on gsk4 gave {code!r}"
    expected = (
        "RANGE key attributes gsk1, gsk2, gsk3 must have equality conditions specified in the "
        "query because a condition is present on key attribute gsk4"
    )
    assert message == expected, f"conditioning only on gsk4: expected {expected!r}, got {message!r}"

    # Positive control: the full equality prefix still returns the item after both rejections.
    got = _poll(ctx, lambda: pks(
        KeyConditionExpression="gpk = :g AND gsk1 = :v1 AND gsk2 = :v2 AND gsk3 = :v3 AND gsk4 = :v4",
        ExpressionAttributeValues={
            ":g": {"S": "g1"}, ":v1": {"S": "a"}, ":v2": {"S": "b"}, ":v3": {"S": "c"}, ":v4": {"S": "d"},
        },
    ), ["p1"])
    assert got == ["p1"], f"the full equality prefix after the rejections selected {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
