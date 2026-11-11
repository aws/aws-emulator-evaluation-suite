"""condition-non-orderable-path-and-size-of-unsupported-type-evaluate-false."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-non-orderable-path-and-size-of-unsupported-type-evaluate-false"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_CCF_MSG = "The conditional request failed"

_BASE = {
    "pk": {"S": "p1"},
    "n": {"N": "5"},
    "num": {"N": "9"},
    "flag": {"BOOL": True},
    "s": {"S": "x"},
    "nu": {"NULL": True},
    "sset": {"SS": ["a", "b"]},
}

# (condition, values) that are well-formed but evaluate to false on _BASE.
_FALSE = [
    ("flag > :zero", {":zero": {"N": "0"}}),
    ("nu > :zero", {":zero": {"N": "0"}}),
    ("nope > :zero", {":zero": {"N": "0"}}),
    ("flag > n", None),
    ("sset > n", None),
    ("n = :bool", {":bool": {"BOOL": True}}),
    ("size(flag) > :zero", {":zero": {"N": "0"}}),
    ("size(nu) > :zero", {":zero": {"N": "0"}}),
    ("size(num) > :zero", {":zero": {"N": "0"}}),
]
# (condition, values) that evaluate to true on _BASE.
_TRUE = [
    ("n <> :bool", {":bool": {"BOOL": True}}),
    ("size(num) <> :zero", {":zero": {"N": "0"}}),
    ("size(s) > :zero", {":zero": {"N": "0"}}),
    ("size(sset) > :zero", {":zero": {"N": "0"}}),
    ("size(sset) = :two", {":two": {"N": "2"}}),
    ("n > :zero", {":zero": {"N": "0"}}),
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


@tags("axis:happy-path", "cap:c2", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Ordering a path that holds BOOL/NULL/a set or nothing, '=' with a BOOL value, and size() of
    an N/BOOL/NULL in a PutItem condition evaluate false (ConditionalCheckFailedException);
    '<>' is true.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-cond-eval-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    key = {"pk": {"S": "p1"}}
    ddb.put_item(TableName=table, Item=_BASE)

    def put(item, condition, values):
        kwargs = {"ConditionExpression": condition}
        if values is not None:
            kwargs["ExpressionAttributeValues"] = values
        return ddb.put_item(TableName=table, Item=item, **kwargs)

    for condition, values in _FALSE:
        changed = {**_BASE, "mark": {"S": condition}}
        code, msg = _error(lambda c=condition, v=values, i=changed: put(i, c, v))
        assert (code, msg) == ("ConditionalCheckFailedException", _CCF_MSG), (
            f"PutItem under {condition!r} gave {code!r}: {msg!r}"
        )
        item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
        assert item == _BASE, f"PutItem under false condition {condition!r} changed the item to {item!r}"

    current = _BASE
    for condition, values in _TRUE:
        changed = {**_BASE, "mark": {"S": condition}}
        put(changed, condition, values)
        item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
        assert item == changed, (
            f"PutItem under true condition {condition!r} left {item!r} (before it: {current!r})"
        )
        current = item


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
