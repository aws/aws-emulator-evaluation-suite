"""empty-string-and-binary-base-table-keys-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "empty-string-and-binary-base-table-keys-rejected"
GROUP = "validation"
SERVICES = ["dynamodb"]

_EMPTY_S_MSG = (
    "One or more parameter values are not valid. The AttributeValue for a key attribute cannot "
    "contain an empty string value. Key: pk"
)
_EMPTY_B_MSG = (
    "One or more parameter values are not valid. The AttributeValue for a key attribute cannot "
    "contain an empty binary value. Key: pk"
)


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


def _create(ctx, ddb, attr_type):
    table = ctx.unique_name(f"sim2real-behav-ddb-emptykey-{attr_type.lower()}-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": attr_type}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    return table


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An empty S or B base-table partition key is refused by PutItem, GetItem, DeleteItem,
    UpdateItem and both BatchWriteItem request kinds, naming the key; nothing is written.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html
    """
    ddb = ctx.client("dynamodb")
    s_table = _create(ctx, ddb, "S")
    b_table = _create(ctx, ddb, "B")
    _wait_active(ddb, ctx, s_table)
    _wait_active(ddb, ctx, b_table)

    # Positive controls: non-empty keys of both types round-trip.
    ddb.put_item(TableName=s_table, Item={"pk": {"S": "ok"}, "v": {"S": "s"}})
    ddb.put_item(TableName=b_table, Item={"pk": {"B": b"ok"}, "v": {"S": "b"}})
    got = ddb.get_item(TableName=s_table, Key={"pk": {"S": "ok"}}, ConsistentRead=True).get("Item")
    assert got == {"pk": {"S": "ok"}, "v": {"S": "s"}}, f"S-keyed control item read back as {got!r}"
    got = ddb.get_item(TableName=b_table, Key={"pk": {"B": b"ok"}}, ConsistentRead=True).get("Item")
    assert got == {"pk": {"B": b"ok"}, "v": {"S": "b"}}, f"B-keyed control item read back as {got!r}"

    arms = []
    for table, empty, msg in ((s_table, {"S": ""}, _EMPTY_S_MSG), (b_table, {"B": b""}, _EMPTY_B_MSG)):
        key = {"pk": empty}
        arms += [
            (f"PutItem {empty!r}", msg,
             lambda t=table, k=key: ddb.put_item(TableName=t, Item={**k, "v": {"S": "x"}})),
            (f"GetItem {empty!r}", msg,
             lambda t=table, k=key: ddb.get_item(TableName=t, Key=k)),
            (f"DeleteItem {empty!r}", msg,
             lambda t=table, k=key: ddb.delete_item(TableName=t, Key=k)),
            (f"UpdateItem {empty!r}", msg,
             lambda t=table, k=key: ddb.update_item(
                 TableName=t, Key=k, UpdateExpression="SET v = :v",
                 ExpressionAttributeValues={":v": {"S": "x"}})),
        ]
    good = {s_table: {"pk": {"S": "batch-good"}}, b_table: {"pk": {"B": b"batch-good"}}}
    for table, empty, msg in ((s_table, {"S": ""}, _EMPTY_S_MSG), (b_table, {"B": b""}, _EMPTY_B_MSG)):
        arms += [
            (f"BatchWriteItem PutRequest {empty!r}", msg,
             lambda t=table, e=empty: ddb.batch_write_item(RequestItems={t: [
                 {"PutRequest": {"Item": good[t]}},
                 {"PutRequest": {"Item": {"pk": e, "v": {"S": "x"}}}},
             ]})),
            (f"BatchWriteItem DeleteRequest {empty!r}", msg,
             lambda t=table, e=empty: ddb.batch_write_item(RequestItems={t: [
                 {"PutRequest": {"Item": good[t]}},
                 {"DeleteRequest": {"Key": {"pk": e}}},
             ]})),
        ]

    for label, msg, call in arms:
        code, got_msg = _error(call)
        assert (code, got_msg) == ("ValidationException", msg), (
            f"{label} gave {code!r}: {got_msg!r}"
        )

    for table in (s_table, b_table):
        absent = ddb.get_item(TableName=table, Key=good[table], ConsistentRead=True).get("Item")
        assert absent is None, f"a refused BatchWriteItem still wrote its valid sibling: {absent!r}"
        count = ddb.scan(TableName=table, Select="COUNT", ConsistentRead=True)["Count"]
        assert count == 1, f"table {table} holds {count!r} items after the refusals, expected 1"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
