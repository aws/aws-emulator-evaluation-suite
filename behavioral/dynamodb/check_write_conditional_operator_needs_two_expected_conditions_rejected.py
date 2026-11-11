"""write-conditional-operator-needs-two-expected-conditions-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "write-conditional-operator-needs-two-expected-conditions-rejected"
GROUP = "validation"
SERVICES = ["dynamodb"]

_WITHOUT_EXPECTED_MSG = (
    "1 validation error detected: ConditionalOperator cannot be used without Filter or Expected"
)
_TWO_OR_MORE_MSG = (
    "1 validation error detected: ConditionalOperator can only be used when Filter or Expected "
    "has two or more elements"
)


def _cond(value):
    """A legacy EQ condition on one string value."""
    return {"ComparisonOperator": "EQ", "AttributeValueList": [{"S": value}]}


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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """ConditionalOperator on PutItem, DeleteItem or UpdateItem without Expected, or with a
    one-condition Expected, is ValidationException and writes nothing; two conditions work.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.ConditionalOperator.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-condop-write-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    key = {"pk": {"S": "k1"}}
    item = {**key, "a": {"S": "x"}, "b": {"S": "y"}}
    ddb.put_item(TableName=table, Item=item)
    new_key = {"pk": {"S": "k2"}}

    cases = [
        ("PutItem with ConditionalOperator and no Expected", _WITHOUT_EXPECTED_MSG,
         lambda: ddb.put_item(TableName=table, Item=new_key, ConditionalOperator="AND")),
        ("DeleteItem with ConditionalOperator and no Expected", _WITHOUT_EXPECTED_MSG,
         lambda: ddb.delete_item(TableName=table, Key=key, ConditionalOperator="AND")),
        ("UpdateItem with ConditionalOperator, AttributeUpdates and no Expected", _WITHOUT_EXPECTED_MSG,
         lambda: ddb.update_item(TableName=table, Key=key, ConditionalOperator="AND",
                                 AttributeUpdates={"a": {"Value": {"S": "v"}, "Action": "PUT"}})),
        ("UpdateItem with only ConditionalOperator", _WITHOUT_EXPECTED_MSG,
         lambda: ddb.update_item(TableName=table, Key=new_key, ConditionalOperator="AND")),
        ("PutItem with ConditionalOperator and a one-condition Expected", _TWO_OR_MORE_MSG,
         lambda: ddb.put_item(TableName=table, Item=new_key, ConditionalOperator="AND",
                              Expected={"a": _cond("x")})),
        ("DeleteItem with ConditionalOperator and a one-condition Expected", _TWO_OR_MORE_MSG,
         lambda: ddb.delete_item(TableName=table, Key=key, ConditionalOperator="AND",
                                 Expected={"a": _cond("x")})),
        ("UpdateItem with ConditionalOperator and a one-condition Expected", _TWO_OR_MORE_MSG,
         lambda: ddb.update_item(TableName=table, Key=key, ConditionalOperator="AND",
                                 AttributeUpdates={"a": {"Value": {"S": "v"}, "Action": "PUT"}},
                                 Expected={"a": _cond("x")})),
    ]
    for label, want, fn in cases:
        code, msg = _error(fn)
        assert (code, msg) == ("ValidationException", want), f"{label} gave {code!r}: {msg!r}"

    items = ddb.scan(TableName=table, ConsistentRead=True)["Items"]
    assert items == [item], f"table after the refused writes holds {items!r}, expected only {item!r}"

    replaced = {**item, "c": {"S": "z"}}
    ddb.put_item(TableName=table, Item=replaced, ConditionalOperator="AND",
                 Expected={"a": _cond("x"), "b": _cond("y")})
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert got == replaced, f"PutItem with a holding two-condition AND Expected left {got!r}"
    ddb.update_item(TableName=table, Key=key, ConditionalOperator="AND",
                    AttributeUpdates={"c": {"Value": {"S": "w"}, "Action": "PUT"}},
                    Expected={"a": _cond("x"), "b": _cond("y")})
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    want = {**replaced, "c": {"S": "w"}}
    assert got == want, f"UpdateItem with a holding two-condition AND Expected left {got!r}"
    ddb.delete_item(TableName=table, Key=key, ConditionalOperator="OR",
                    Expected={"a": _cond("x"), "b": _cond("nope")})
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert got is None, f"DeleteItem with a holding two-condition OR Expected left {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
