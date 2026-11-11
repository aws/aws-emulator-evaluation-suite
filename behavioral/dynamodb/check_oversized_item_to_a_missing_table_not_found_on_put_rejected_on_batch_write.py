"""oversized-item-to-a-missing-table-not-found-on-put-rejected-on-batch-write."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "oversized-item-to-a-missing-table-not-found-on-put-rejected-on-batch-write"
GROUP = "validation"
SERVICES = ["dynamodb"]

_NOT_FOUND = ("ResourceNotFoundException", "Requested resource not found")
_TOO_BIG = ("ValidationException", "Item size has exceeded the maximum allowed size")
_ITEM_LIMIT_BYTES = 400 * 1024


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An item over 400 KB sent by PutItem to a missing table is ResourceNotFound, by BatchWriteItem
    the item-size ValidationException; to an existing table both refuse it by size and store nothing.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-bigitem-")
    missing = f"{table}-absent"
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    big = {"pk": {"S": "big"}, "blob": {"S": "x" * _ITEM_LIMIT_BYTES}}

    def put(name):
        return ddb.put_item(TableName=name, Item=big)

    def batch(name):
        return ddb.batch_write_item(RequestItems={name: [{"PutRequest": {"Item": big}}]})

    # PutItem looks the table up before sizing the item; BatchWriteItem sizes it first.
    for label, fn, want in (("PutItem", put, _NOT_FOUND), ("BatchWriteItem", batch, _TOO_BIG)):
        code, msg = _error(lambda f=fn: f(missing))
        assert (code, msg) == want, f"{label} of an oversized item to the missing table gave {code!r}: {msg!r}"
        code, msg = _error(lambda f=fn: f(table))
        assert (code, msg) == _TOO_BIG, f"{label} of an oversized item to the existing table gave {code!r}: {msg!r}"

    gone = ddb.get_item(TableName=table, Key={"pk": {"S": "big"}}, ConsistentRead=True)
    assert "Item" not in gone, f"the oversized item was stored: {sorted(gone['Item'])!r}"
    ddb.put_item(TableName=table, Item={"pk": {"S": "small"}, "blob": {"S": "x"}})
    small = ddb.get_item(TableName=table, Key={"pk": {"S": "small"}}, ConsistentRead=True).get("Item")
    assert small == {"pk": {"S": "small"}, "blob": {"S": "x"}}, f"the small control item reads back {small!r}"
    code, msg = _error(lambda: ddb.describe_table(TableName=missing))
    want = ("ResourceNotFoundException", f"Requested resource not found: Table: {missing} not found")
    assert (code, msg) == want, f"the missing table describes as {code!r}: {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
