"""condition-nested-path-type-mismatch-fails-the-condition."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-nested-path-type-mismatch-fails-the-condition"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_CCF_MSG = "The conditional request failed"

_DOC = {
    "m": {"M": {"k": {"S": "inner"}, "mm": {"M": {"k": {"S": "deep"}}}}},
    "l": {"L": [{"M": {"k": {"S": "first"}}}, {"S": "s"}]},
}
_NAMES = {"#m": "m", "#k": "k", "#mm": "mm", "#l": "l", "#z": "z", "#u": "u"}
_FAILS = [
    "attribute_exists(#m.#z)",
    "attribute_not_exists(#m.#k)",
    "#m.#k <> :inner",
    "attribute_exists(#l.#k)",
    "attribute_exists(#m[0])",
    "#m.#k = :other OR #m.#mm.#k = :other OR #l[0].#k = :other",
]


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


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A condition dereferencing a list member by name, indexing a map, or comparing nested members
    that differ is ConditionalCheckFailedException on UpdateItem and DeleteItem; item unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.Attributes.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-nested-fail-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    key = {"pk": {"S": "nested"}}
    original = {**key, **_DOC}
    ddb.put_item(TableName=table, Item=original)
    values = {":x": {"S": "z"}, ":inner": {"S": "inner"}, ":other": {"S": "other"}}

    for condition in _FAILS:
        tokens = set(re.findall(r"[#:][A-Za-z0-9_]+", condition)) | {"#u", ":x"}
        names = {k: v for k, v in _NAMES.items() if k in tokens}
        vals = {k: v for k, v in values.items() if k in tokens}
        code, msg = _error(lambda c=condition, n=names, v=vals: ddb.update_item(
            TableName=table, Key=key, UpdateExpression="SET #u = :x", ConditionExpression=c,
            ExpressionAttributeNames=n, ExpressionAttributeValues=v))
        assert (code, msg) == ("ConditionalCheckFailedException", _CCF_MSG), (
            f"UpdateItem under {condition!r} gave {code!r}: {msg!r}"
        )
        item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
        assert item == original, f"UpdateItem under failing {condition!r} changed the item to {item!r}"

    code, msg = _error(lambda: ddb.delete_item(
        TableName=table, Key=key, ConditionExpression="#m.#mm.#k = :other",
        ExpressionAttributeNames={"#m": "m", "#mm": "mm", "#k": "k"},
        ExpressionAttributeValues={":other": {"S": "other"}}))
    assert (code, msg) == ("ConditionalCheckFailedException", _CCF_MSG), (
        f"DeleteItem under '#m.#mm.#k = :other' gave {code!r}: {msg!r}"
    )
    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert item == original, f"DeleteItem under a failing nested condition left {item!r}"

    ddb.update_item(TableName=table, Key=key, UpdateExpression="SET #u = :x",
                    ConditionExpression="#l[0].#k = :first",
                    ExpressionAttributeNames={"#u": "u", "#l": "l", "#k": "k"},
                    ExpressionAttributeValues={":x": {"S": "z"}, ":first": {"S": "first"}})
    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert item == {**original, "u": {"S": "z"}}, f"UpdateItem under a holding condition left {item!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
