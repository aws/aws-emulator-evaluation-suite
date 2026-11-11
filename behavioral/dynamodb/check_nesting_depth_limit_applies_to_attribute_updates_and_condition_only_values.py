"""nesting-depth-limit-applies-to-attribute-updates-and-condition-only-values."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nesting-depth-limit-applies-to-attribute-updates-and-condition-only-values"
GROUP = "limits"
SERVICES = ["dynamodb"]

_NESTING_MSG = (
    "1 validation error detected: Nesting Levels have exceeded supported limits: "
    "Attributes in the item have nested levels beyond supported limit"
)
_OVER_LIMIT_WRAPPERS = 32
_AT_LIMIT_WRAPPERS = 31


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


def _deep_map(wrappers):
    """`wrappers` nested single-member M levels around an S leaf."""
    value = {"S": "leaf"}
    for _ in range(wrappers):
        value = {"M": {"a": value}}
    return value


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A value one level past the nesting limit is refused in AttributeUpdates, inside
    if_not_exists, and when only a DeleteItem or UpdateItem condition reads it; one level less works.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-depth-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    key = {"pk": {"S": "target"}}
    seeded = {**key, "v": {"S": "orig"}}
    ddb.put_item(TableName=table, Item=seeded)
    deep = _deep_map(_OVER_LIMIT_WRAPPERS)

    code, msg = _error(lambda: ddb.update_item(
        TableName=table, Key=key,
        AttributeUpdates={"deep": {"Action": "PUT", "Value": deep}},
    ))
    assert (code, msg) == ("ValidationException", _NESTING_MSG), (
        f"AttributeUpdates PUT of an over-deep value gave {code!r}: {msg!r}"
    )

    code, msg = _error(lambda: ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET deep = if_not_exists(deep, :d)",
        ExpressionAttributeValues={":d": deep},
    ))
    assert (code, msg) == ("ValidationException", _NESTING_MSG), (
        f"SET deep = if_not_exists(deep, :d) with an over-deep :d gave {code!r}: {msg!r}"
    )

    code, msg = _error(lambda: ddb.delete_item(
        TableName=table, Key=key,
        ConditionExpression="attribute_exists(pk) OR :d = :d",
        ExpressionAttributeValues={":d": deep},
    ))
    assert (code, msg) == ("ValidationException", _NESTING_MSG), (
        f"DeleteItem with an over-deep condition-only value gave {code!r}: {msg!r}"
    )

    code, msg = _error(lambda: ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET v = :s",
        ConditionExpression="attribute_exists(pk) OR :d = :d",
        ExpressionAttributeValues={":s": {"S": "changed"}, ":d": deep},
    ))
    assert (code, msg) == ("ValidationException", _NESTING_MSG), (
        f"UpdateItem with an over-deep condition-only value gave {code!r}: {msg!r}"
    )

    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert item == seeded, f"after four refused requests the item is {item!r}, expected {seeded!r}"

    # Positive control: one level shallower, a condition-only value is accepted.
    ctl_key = {"pk": {"S": "at-limit"}}
    ddb.put_item(
        TableName=table, Item={**ctl_key, "v": {"S": "ok"}},
        ConditionExpression="attribute_not_exists(pk) OR :d = :d",
        ExpressionAttributeValues={":d": _deep_map(_AT_LIMIT_WRAPPERS)},
    )
    ctl = ddb.get_item(TableName=table, Key=ctl_key, ConsistentRead=True).get("Item")
    assert ctl == {**ctl_key, "v": {"S": "ok"}}, (
        f"PutItem with an at-limit condition-only value stored {ctl!r}"
    )

    shallow = _deep_map(_AT_LIMIT_WRAPPERS)
    ddb.update_item(TableName=table, Key=ctl_key,
                    AttributeUpdates={"deep": {"Action": "PUT", "Value": shallow}})
    ctl = ddb.get_item(TableName=table, Key=ctl_key, ConsistentRead=True).get("Item")
    want = {**ctl_key, "v": {"S": "ok"}, "deep": shallow}
    assert ctl == want, f"AttributeUpdates PUT of an at-limit value left {ctl!r}"

    ddb.update_item(TableName=table, Key=ctl_key,
                    UpdateExpression="SET deep2 = if_not_exists(deep2, :d)",
                    ExpressionAttributeValues={":d": shallow})
    ctl = ddb.get_item(TableName=table, Key=ctl_key, ConsistentRead=True).get("Item")
    want = {**want, "deep2": shallow}
    assert ctl == want, f"SET deep2 = if_not_exists(deep2, :d) with an at-limit :d left {ctl!r}"

    ddb.update_item(TableName=table, Key=ctl_key, UpdateExpression="SET v = :s",
                    ConditionExpression="attribute_exists(pk) OR :d = :d",
                    ExpressionAttributeValues={":s": {"S": "changed"}, ":d": shallow})
    ctl = ddb.get_item(TableName=table, Key=ctl_key, ConsistentRead=True).get("Item")
    want = {**want, "v": {"S": "changed"}}
    assert ctl == want, f"UpdateItem with an at-limit condition-only value left {ctl!r}"

    ddb.delete_item(TableName=table, Key=ctl_key,
                    ConditionExpression="attribute_exists(pk) OR :d = :d",
                    ExpressionAttributeValues={":d": shallow})
    ctl = ddb.get_item(TableName=table, Key=ctl_key, ConsistentRead=True).get("Item")
    assert ctl is None, f"DeleteItem with an at-limit condition-only value left {ctl!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
