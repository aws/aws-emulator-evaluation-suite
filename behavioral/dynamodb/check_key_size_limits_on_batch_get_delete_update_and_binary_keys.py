"""key-size-limits-on-batch-get-delete-update-and-binary-keys."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "key-size-limits-on-batch-get-delete-update-and-binary-keys"
GROUP = "validation"
SERVICES = ["dynamodb"]

_HASH_MAX = 2048
_RANGE_MAX = 1024
_HASH_MSG = (
    "One or more parameter values were invalid: Size of hashkey has exceeded the maximum size "
    "limit of2048 bytes"
)
_RANGE_MSG = (
    "One or more parameter values were invalid: Aggregated size of all range keys has exceeded "
    "the size limit of 1024 bytes"
)
_NOT_FOUND_MSG = "Requested resource not found"


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


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Over-size hash/range keys are refused by BatchGetItem, DeleteItem, UpdateItem and (decoded
    B length) GetItem; at-limit keys work; a missing table answers not-found first.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html
    """
    ddb = ctx.client("dynamodb")
    hr_table = ctx.unique_name("sim2real-behav-ddb-keysize-hr-")
    ddb.create_table(
        TableName=hr_table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=hr_table), "ResourceNotFoundException"))
    b_table = ctx.unique_name("sim2real-behav-ddb-keysize-b-")
    ddb.create_table(
        TableName=b_table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "B"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=b_table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, hr_table)
    _wait_active(ddb, ctx, b_table)

    big_hash = "a" * (_HASH_MAX + 1)
    big_range = "b" * (_RANGE_MAX + 1)
    limit_key = {"pk": {"S": "a" * _HASH_MAX}, "sk": {"S": "b" * _RANGE_MAX}}
    seeded = {**limit_key, "v": {"S": "at-limit"}}
    ddb.put_item(TableName=hr_table, Item=seeded)

    # Positive control: BatchGetItem with at-limit keys returns the item.
    resp = ddb.batch_get_item(RequestItems={hr_table: {"Keys": [limit_key], "ConsistentRead": True}})
    got = resp["Responses"].get(hr_table)
    assert got == [seeded], f"BatchGetItem with at-limit keys returned {got!r}"

    arms = [
        ("BatchGetItem over-size hash key", _HASH_MSG, lambda: ddb.batch_get_item(RequestItems={
            hr_table: {"Keys": [{"pk": {"S": big_hash}, "sk": {"S": "s"}}]}})),
        ("BatchGetItem over-size range key", _RANGE_MSG, lambda: ddb.batch_get_item(RequestItems={
            hr_table: {"Keys": [{"pk": {"S": "h"}, "sk": {"S": big_range}}]}})),
        ("DeleteItem over-size hash key", _HASH_MSG, lambda: ddb.delete_item(
            TableName=hr_table, Key={"pk": {"S": big_hash}, "sk": {"S": "s"}})),
        ("UpdateItem over-size range key", _RANGE_MSG, lambda: ddb.update_item(
            TableName=hr_table, Key={"pk": {"S": "h"}, "sk": {"S": big_range}},
            UpdateExpression="SET x = :v", ExpressionAttributeValues={":v": {"S": "1"}})),
        ("GetItem B hash key of 2049 decoded bytes", _HASH_MSG, lambda: ddb.get_item(
            TableName=b_table, Key={"pk": {"B": b"a" * (_HASH_MAX + 1)}})),
    ]
    for label, msg, call in arms:
        code, got_msg = _error(call)
        assert (code, got_msg) == ("ValidationException", msg), f"{label} gave {code!r}: {got_msg!r}"

    count = ddb.scan(TableName=hr_table, Select="COUNT", ConsistentRead=True)["Count"]
    assert count == 1, f"the refused key-size requests left {count!r} items, expected 1"

    ddb.update_item(TableName=hr_table, Key=limit_key, UpdateExpression="SET x = :v",
                    ExpressionAttributeValues={":v": {"S": "1"}})
    got = ddb.get_item(TableName=hr_table, Key=limit_key, ConsistentRead=True).get("Item")
    assert got == {**seeded, "x": {"S": "1"}}, f"UpdateItem with at-limit keys left {got!r}"
    ddb.delete_item(TableName=hr_table, Key=limit_key)
    got = ddb.get_item(TableName=hr_table, Key=limit_key, ConsistentRead=True).get("Item")
    assert got is None, f"DeleteItem with at-limit keys left {got!r}"

    # A B key exactly at the limit (decoded) is accepted on write and read.
    b_limit = {"pk": {"B": b"a" * _HASH_MAX}}
    resp = ddb.get_item(TableName=b_table, Key=b_limit, ConsistentRead=True)
    assert "Item" not in resp, f"GetItem with an at-limit B key on an empty table returned {resp.get('Item')!r}"
    ddb.put_item(TableName=b_table, Item={**b_limit, "v": {"S": "b"}})
    got = ddb.get_item(TableName=b_table, Key=b_limit, ConsistentRead=True).get("Item")
    assert got == {**b_limit, "v": {"S": "b"}}, f"the at-limit B-keyed item read back as {got!r}"

    missing = ctx.unique_name("sim2real-behav-ddb-keysize-missing-")
    code, msg = _error(lambda: ddb.get_item(TableName=missing, Key={"pk": {"S": big_hash}}))
    assert (code, msg) == ("ResourceNotFoundException", _NOT_FOUND_MSG), (
        f"GetItem with an over-size key on a missing table gave {code!r}: {msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
