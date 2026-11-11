"""condition-nested-document-paths-that-hold-apply-the-write."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-nested-document-paths-that-hold-apply-the-write"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_NAMES = {
    "#m": "m", "#k": "k", "#n": "n", "#mm": "mm", "#l": "l", "#z": "z", "#u": "u",
    "#t": "t", "#M": "M", "#L": "L", "#S": "S", "#zero": "0", "#g": "g",
}
_COND_FAILED = "The conditional request failed"
_VALUES = {
    ":inner": {"S": "inner"}, ":deep": {"S": "deep"}, ":first": {"S": "first"}, ":b": {"S": "b"},
    ":in": {"S": "in"}, ":ner": {"S": "ner"}, ":S": {"S": "S"}, ":M": {"S": "M"}, ":s": {"S": "s"},
    ":tm": {"S": "tm"}, ":tl": {"S": "tl"}, ":ts": {"S": "ts"}, ":t0": {"S": "t0"},
    ":g21": {"S": "g21"},
}
_DOC = {
    "m": {"M": {
        "k": {"S": "inner"},
        "n": {"L": [{"N": "10"}, {"S": "b"}]},
        "mm": {"M": {"k": {"S": "deep"}}},
    }},
    "l": {"L": [{"M": {"k": {"S": "first"}}}, {"S": "s"}]},
    "t": {"M": {"M": {"S": "tm"}, "L": {"S": "tl"}, "S": {"S": "ts"}, "0": {"S": "t0"}}},
    "g": {"L": [{"S": "g0"}, {"S": "g1"}, {"L": [{"S": "g20"}, {"S": "g21"}]}]},
}
_HOLDS = [
    "attribute_exists(#m.#k)",
    "attribute_not_exists(#m.#z)",
    "#m.#k = :inner",
    "begins_with(#m.#k, :in)",
    "contains(#m.#k, :ner)",
    "attribute_type(#m.#k, :S)",
    "attribute_type(#m.#mm, :M)",
    "#m.#mm.#k = :deep",
    "#l[0].#k = :first",
    "#m.#n[1] = :b",
    "#l[1] = :s",
    "attribute_exists(#m.#k) AND #m.#mm.#k = :deep AND #l[0].#k = :first",
    "NOT attribute_exists(#m.#mm.#z)",
    "#t.#M = :tm",
    "#t.#L = :tl",
    "#t.#S = :ts",
    "#t.#zero = :t0",
    "#g[2][1] = :g21",
]


def _maps(*exprs):
    """The EAN/EAV entries the given expressions reference."""
    tokens = set(re.findall(r"[#:][A-Za-z0-9_]+", " ".join(exprs)))
    out = {"ExpressionAttributeNames": {k: v for k, v in _NAMES.items() if k in tokens}}
    values = {k: v for k, v in _VALUES.items() if k in tokens}
    if values:
        out["ExpressionAttributeValues"] = values
    return out


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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c2", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem and DeleteItem conditions on map members, list elements, nested lists and members
    named like type tags or digits that hold apply the write; a near-miss path fails the condition.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.Attributes.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-nested-hold-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                   {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    key = {"pk": {"S": "nested"}, "sk": {"S": "item"}}
    ddb.put_item(TableName=table, Item={**key, **_DOC})

    for i, condition in enumerate(_HOLDS):
        maps = _maps("SET #u = :x", condition)
        maps["ExpressionAttributeValues"] = {**maps.get("ExpressionAttributeValues", {}),
                                             ":x": {"S": f"u{i}"}}
        ddb.update_item(TableName=table, Key=key, UpdateExpression="SET #u = :x",
                        ConditionExpression=condition, **maps)
        item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
        want = {**key, **_DOC, "u": {"S": f"u{i}"}}
        assert item == want, f"UpdateItem under holding condition {condition!r} left {item!r}"

    near_miss = "#m.#mm.#k = :inner"
    maps = _maps("SET #u = :x", near_miss)
    maps["ExpressionAttributeValues"] = {**maps["ExpressionAttributeValues"], ":x": {"S": "miss"}}
    code, msg = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET #u = :x",
        ConditionExpression=near_miss, **maps))
    assert (code, msg) == ("ConditionalCheckFailedException", _COND_FAILED), (
        f"UpdateItem under failing condition {near_miss!r} gave {code!r}: {msg!r}")
    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    want = {**key, **_DOC, "u": {"S": f"u{len(_HOLDS) - 1}"}}
    assert item == want, f"UpdateItem under failing condition {near_miss!r} left {item!r}"

    condition = "#m.#mm.#k = :deep AND #l[0].#k = :first AND #g[2][1] = :g21"
    ddb.delete_item(TableName=table, Key=key, ConditionExpression=condition, **_maps(condition))
    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert item is None, f"DeleteItem under holding condition {condition!r} left {item!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
