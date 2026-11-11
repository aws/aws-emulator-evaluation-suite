"""query-gsi-multi-range-key-schema-requires-equality-prefix."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-gsi-multi-range-key-schema-requires-equality-prefix"
GROUP = "gsi"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"
_INDEX = "by-three-range"


def _error(fn) -> tuple:
    """The (code, message) ``fn`` is refused with. An unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll(read, done, *, ctx, poll_s: float):
    """``read()`` until ``done(value)``, bounded by ``ctx.time_left()``."""
    while True:
        value = read()
        if done(value):
            return value
        left = ctx.time_left()
        if left is not None and left <= poll_s:
            raise AssertionError(f"condition not met before the budget ran out; last value {value!r}")
        time.sleep(poll_s)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GSI keyed on one HASH and three RANGE attributes requires an equality condition on every
    RANGE attribute before the last one referenced; skipping or under-constraining one
    is ValidationException naming it, while the full equality prefix returns the matching item.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-mr-")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ["pk", "gpk", "gsk1", "gsk2", "gsk3"]],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [
                {"AttributeName": "gpk", "KeyType": "HASH"},
                {"AttributeName": "gsk1", "KeyType": "RANGE"},
                {"AttributeName": "gsk2", "KeyType": "RANGE"},
                {"AttributeName": "gsk3", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    desc = _poll(
        lambda: ddb.describe_table(TableName=table)["Table"],
        lambda t: t["TableStatus"] == "ACTIVE" and all(g["IndexStatus"] == "ACTIVE" for g in t["GlobalSecondaryIndexes"]),
        ctx=ctx, poll_s=5.0,
    )
    key_schema = desc["GlobalSecondaryIndexes"][0]["KeySchema"]
    assert key_schema == [
        {"AttributeName": "gpk", "KeyType": "HASH"},
        {"AttributeName": "gsk1", "KeyType": "RANGE"},
        {"AttributeName": "gsk2", "KeyType": "RANGE"},
        {"AttributeName": "gsk3", "KeyType": "RANGE"},
    ], f"the GSI describes its key as {key_schema!r}"

    ddb.put_item(TableName=table, Item={
        "pk": {"S": "p1"}, "gpk": {"S": "g1"}, "gsk1": {"S": "a"}, "gsk2": {"S": "b"}, "gsk3": {"S": "c"},
    })

    def query(**kwargs):
        return ddb.query(TableName=table, IndexName=_INDEX, **kwargs)

    def pks(**cond) -> list:
        items = []
        for page in ddb.get_paginator("query").paginate(TableName=table, IndexName=_INDEX, **cond):
            items.extend(page["Items"])
        return sorted(i["pk"]["S"] for i in items)

    # Positive control: the full equality prefix (hash plus every RANGE attribute) returns the item.
    full_prefix = dict(
        KeyConditionExpression="gpk = :g AND gsk1 = :g1 AND gsk2 = :g2 AND gsk3 = :g3",
        ExpressionAttributeValues={":g": {"S": "g1"}, ":g1": {"S": "a"}, ":g2": {"S": "b"}, ":g3": {"S": "c"}},
    )
    got = _poll(lambda: pks(**full_prefix), lambda v: v == ["p1"], ctx=ctx, poll_s=2.0)
    assert got == ["p1"], f"the full equality prefix selected {got!r}"

    # Skipping the first RANGE attribute (gsk1): a condition on gsk2 alone is refused, naming
    # the skipped attribute and the one whose presence required it.
    code, message = _error(lambda: query(
        KeyConditionExpression="gpk = :g AND gsk2 = :g2",
        ExpressionAttributeValues={":g": {"S": "g1"}, ":g2": {"S": "b"}},
    ))
    assert code == ERR_VALIDATION, f"skipping gsk1 gave {code!r}"
    expected = "RANGE key attributes gsk1 must have equality conditions specified in the query because a condition is present on key attribute gsk2"
    assert message == expected, f"skipping gsk1: expected {expected!r}, got {message!r}"

    # Skipping a middle attribute: gsk1 and gsk3 are conditioned but gsk2 (in between) is not.
    code, message = _error(lambda: query(
        KeyConditionExpression="gpk = :g AND gsk1 = :g1 AND gsk3 = :g3",
        ExpressionAttributeValues={":g": {"S": "g1"}, ":g1": {"S": "a"}, ":g3": {"S": "c"}},
    ))
    assert code == ERR_VALIDATION, f"skipping gsk2 gave {code!r}"
    expected = "RANGE key attributes gsk2 must have equality conditions specified in the query because a condition is present on key attribute gsk3"
    assert message == expected, f"skipping gsk2: expected {expected!r}, got {message!r}"

    # Placing a range comparison on gsk1 (not the last RANGE attribute referenced) while gsk2
    # carries a condition too: gsk1's comparator must be equality, not merely present.
    code, message = _error(lambda: query(
        KeyConditionExpression="gpk = :g AND gsk1 > :g1 AND gsk2 = :g2",
        ExpressionAttributeValues={":g": {"S": "g1"}, ":g1": {"S": "a"}, ":g2": {"S": "b"}},
    ))
    assert code == ERR_VALIDATION, f"a non-equality comparator on gsk1 before gsk2 gave {code!r}"
    expected = "RANGE key attributes gsk1 must have equality conditions specified in the query because a condition is present on key attribute gsk2"
    assert message == expected, f"a non-equality comparator on gsk1 before gsk2: expected {expected!r}, got {message!r}"

    # Final control: a non-equality comparator IS allowed on the last RANGE attribute referenced,
    # and the full equality prefix still answers correctly after every rejection above.
    got = pks(
        KeyConditionExpression="gpk = :g AND gsk1 = :g1 AND gsk2 = :g2 AND gsk3 > :g3",
        ExpressionAttributeValues={":g": {"S": "g1"}, ":g1": {"S": "a"}, ":g2": {"S": "b"}, ":g3": {"S": "a"}},
    )
    assert got == ["p1"], f"a range comparison on the last referenced RANGE attribute selected {got!r}"

    got = pks(
        KeyConditionExpression="gpk = :g AND gsk1 = :g1 AND gsk2 = :g2",
        ExpressionAttributeValues={":g": {"S": "g1"}, ":g1": {"S": "a"}, ":g2": {"S": "b"}},
    )
    assert got == ["p1"], f"the equality prefix after the rejections selected {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
