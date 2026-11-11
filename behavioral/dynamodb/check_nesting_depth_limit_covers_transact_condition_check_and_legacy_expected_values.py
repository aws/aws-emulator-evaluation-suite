"""nesting-depth-limit-covers-transact-condition-check-and-legacy-expected-values."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nesting-depth-limit-covers-transact-condition-check-and-legacy-expected-values"
GROUP = "limits"
SERVICES = ["dynamodb"]

_OVER_LIMIT_WRAPPERS = 32
_AT_LIMIT_WRAPPERS = 31
_NESTING_MSG = (
    "Nesting Levels have exceeded supported limits: Attributes in the item have nested levels beyond "
    "supported limit"
)
_TRANSACT_CONDITION_CHECK_DEEP_MSG = _NESTING_MSG
_LEGACY_EXPECTED_DEEP_MSG = "1 validation error detected: " + _NESTING_MSG


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
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
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


def _deep_map(wrappers, leaf):
    """`wrappers` nested single-member M levels around `leaf`."""
    value = leaf
    for _ in range(wrappers):
        value = {"M": {"a": value}}
    return value


def _leaf_of(value, wrappers):
    for _ in range(wrappers):
        value = value["M"]["a"]
    return value


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An over-deep value in a TransactWriteItems ConditionCheck or a legacy Expected Value is
    ValidationException and writes nothing; a number set at the deepest accepted level is stored.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-depthok-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    def get(pk):
        return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")

    # A number-set leaf under the deepest accepted map chain is stored and reads back.
    doc = _deep_map(_AT_LIMIT_WRAPPERS, {"NS": ["1", "2"]})
    ddb.put_item(TableName=table, Item={"pk": {"S": "ns"}, "doc": doc})
    stored = get("ns")
    assert stored is not None, "PutItem of an at-limit map chain around a number set stored nothing"
    leaf = _leaf_of(stored["doc"], _AT_LIMIT_WRAPPERS)
    assert sorted(leaf.get("NS", [])) == ["1", "2"] and list(leaf) == ["NS"], (
        f"the number-set leaf read back as {leaf!r}"
    )

    seeded = {"pk": {"S": "target"}, "v": {"S": "orig"}}
    ddb.put_item(TableName=table, Item=seeded)
    deep = _deep_map(_OVER_LIMIT_WRAPPERS, {"S": "leaf"})

    code, msg = _error(lambda: ddb.transact_write_items(TransactItems=[
        {"ConditionCheck": {
            "TableName": table, "Key": {"pk": {"S": "target"}},
            "ConditionExpression": "attribute_exists(pk) OR :d = :d",
            "ExpressionAttributeValues": {":d": deep},
        }},
        {"Put": {"TableName": table, "Item": {"pk": {"S": "marker"}}}},
    ]))
    assert (code, msg) == ("ValidationException", _TRANSACT_CONDITION_CHECK_DEEP_MSG), (
        f"TransactWriteItems ConditionCheck with an over-deep value gave {code!r}: {msg!r}"
    )
    marker = get("marker")
    assert marker is None, f"the refused transaction's Put left {marker!r}"
    item = get("target")
    assert item == seeded, f"after the refused transaction the target item is {item!r}"

    code, msg = _error(lambda: ddb.update_item(
        TableName=table, Key={"pk": {"S": "target"}},
        AttributeUpdates={"myattr": {"Action": "PUT", "Value": {"S": "x"}}},
        Expected={"deep": {"Value": deep}},
    ))
    assert (code, msg) == ("ValidationException", _LEGACY_EXPECTED_DEEP_MSG), (
        f"UpdateItem with an over-deep legacy Expected Value gave {code!r}: {msg!r}"
    )
    item = get("target")
    assert item == seeded, f"after the refused legacy Expected update the item is {item!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
