"""delete-item-condition-function-pins-size-nested-absence-bs-type-and-members."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-condition-function-pins-size-nested-absence-bs-type-and-members"
GROUP = "conditions"
SERVICES = ["dynamodb"]
_COND_FAILED = ("ConditionalCheckFailedException", "The conditional request failed")


def _unordered_sets(item):
    """``item`` with every set member list sorted: DynamoDB sets carry no member order."""
    if item is None:
        return None
    return {
        name: {t: sorted(v) if t in ("SS", "NS", "BS") else v for t, v in value.items()}
        for name, value in item.items()
    }


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success fails too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A DeleteItem ConditionExpression gates the delete on the stored value of size() BETWEEN
    bounds and size() = length on a String, attribute_not_exists() on an absent nested map child,
    attribute_type() naming BS, begins_with() with a Binary prefix, and contains() on a Binary Set."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-del-fns-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    def pin(key, item, condition, names_values, bad_names_values):
        """Put ``item``, prove ``condition`` refuses under ``bad_names_values``, then delete it
        under ``names_values`` and prove the delete landed."""
        ddb.put_item(TableName=table, Item=item)
        expect_error(
            lambda: ddb.delete_item(TableName=table, Key=key, ConditionExpression=condition,
                                    **bad_names_values),
            *_COND_FAILED,
        )
        still = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
        assert _unordered_sets(still) == _unordered_sets(item), (
            f"DeleteItem refused under {condition!r} left {still!r}, expected {item!r}"
        )

        ddb.delete_item(TableName=table, Key=key, ConditionExpression=condition, **names_values)
        gone = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
        assert gone is None, f"DeleteItem under holding {condition!r} left {gone!r}"

    # --- size(string) BETWEEN bounds holds: "AnyCompany" has length 10. ---
    key1 = {"pk": {"S": "size-between"}}
    pin(
        key1, {**key1, "name": {"S": "AnyCompany"}},
        "size(#n) BETWEEN :lo AND :hi",
        {"ExpressionAttributeNames": {"#n": "name"},
         "ExpressionAttributeValues": {":lo": {"N": "5"}, ":hi": {"N": "15"}}},
        {"ExpressionAttributeNames": {"#n": "name"},
         "ExpressionAttributeValues": {":lo": {"N": "11"}, ":hi": {"N": "20"}}},
    )

    # --- size(string) equals its length: "Example Corp" has length 12. ---
    key2 = {"pk": {"S": "size-eq"}}
    pin(
        key2, {**key2, "name": {"S": "Example Corp"}},
        "size(#n) = :len",
        {"ExpressionAttributeNames": {"#n": "name"}, "ExpressionAttributeValues": {":len": {"N": "12"}}},
        {"ExpressionAttributeNames": {"#n": "name"}, "ExpressionAttributeValues": {":len": {"N": "99"}}},
    )

    # --- attribute_not_exists() on an absent nested map child holds; the same path refuses when
    # the child is present on a sibling item. ---
    key3 = {"pk": {"S": "nested-absent"}}
    present_item = {**key3, "m": {"M": {"k": {"S": "present"}, "child": {"S": "here"}}}}
    ddb.put_item(TableName=table, Item=present_item)
    expect_error(
        lambda: ddb.delete_item(TableName=table, Key=key3,
                                ConditionExpression="attribute_not_exists(#m.#c)",
                                ExpressionAttributeNames={"#m": "m", "#c": "child"}),
        *_COND_FAILED,
    )
    still = ddb.get_item(TableName=table, Key=key3, ConsistentRead=True).get("Item")
    assert still == present_item, f"DeleteItem refused under attribute_not_exists left {still!r}"

    absent_item = {**key3, "m": {"M": {"k": {"S": "present"}}}}
    ddb.put_item(TableName=table, Item=absent_item)
    ddb.delete_item(TableName=table, Key=key3, ConditionExpression="attribute_not_exists(#m.#c)",
                    ExpressionAttributeNames={"#m": "m", "#c": "child"})
    gone = ddb.get_item(TableName=table, Key=key3, ConsistentRead=True).get("Item")
    assert gone is None, f"DeleteItem under holding attribute_not_exists(m.child) left {gone!r}"

    # --- attribute_type() naming BS matches a stored Binary Set. ---
    key4 = {"pk": {"S": "attrtype-bs"}}
    pin(
        key4, {**key4, "bs": {"BS": [b"\x01", b"\x02"]}},
        "attribute_type(#bs, :t)",
        {"ExpressionAttributeNames": {"#bs": "bs"}, "ExpressionAttributeValues": {":t": {"S": "BS"}}},
        {"ExpressionAttributeNames": {"#bs": "bs"}, "ExpressionAttributeValues": {":t": {"S": "S"}}},
    )

    # --- begins_with() with a Binary prefix on a plain (non-key) attribute. ---
    key5 = {"pk": {"S": "beginswith-b"}}
    pin(
        key5, {**key5, "blob": {"B": b"\x01\x02\x03"}},
        "begins_with(#b, :p)",
        {"ExpressionAttributeNames": {"#b": "blob"}, "ExpressionAttributeValues": {":p": {"B": b"\x01\x02"}}},
        {"ExpressionAttributeNames": {"#b": "blob"}, "ExpressionAttributeValues": {":p": {"B": b"\x09"}}},
    )

    # --- contains() testing a Binary Set member. ---
    key6 = {"pk": {"S": "contains-bs"}}
    pin(
        key6, {**key6, "bs": {"BS": [b"\xaa", b"\xbb"]}},
        "contains(#bs, :m)",
        {"ExpressionAttributeNames": {"#bs": "bs"}, "ExpressionAttributeValues": {":m": {"B": b"\xaa"}}},
        {"ExpressionAttributeNames": {"#bs": "bs"}, "ExpressionAttributeValues": {":m": {"B": b"\xcc"}}},
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
