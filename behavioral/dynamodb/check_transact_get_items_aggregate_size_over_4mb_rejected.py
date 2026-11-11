"""transact-get-items-aggregate-size-over-4mb-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-get-items-aggregate-size-over-4mb-rejected"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_FILLER_BYTES = 390 * 1024
_OVER_LIMIT_ITEMS = 11
_UNDER_LIMIT_ITEMS = 10
_TOO_LARGE = ("ValidationException", "Payload in response is too large.")


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


def _create_table(ctx, ddb, prefix):
    """Create an on-demand table keyed pk (S) and wait until ACTIVE."""
    table = ctx.unique_name(prefix)
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    return table


def _error(fn):
    """(Error.Code, Error.Message, CancellationReasons) of the ClientError fn() raises.

    An unexpected success fails, quoting the result.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message"), exc.response.get("CancellationReasons")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _item(pk):
    """An item of one short key and one ~390 KB string attribute."""
    return {"pk": {"S": pk}, "data": {"S": "x" * _FILLER_BYTES}}


def _item_size(item):
    """The DynamoDB size of an all-string item: attribute-name bytes plus value bytes."""
    return sum(len(name.encode()) + len(value["S"].encode()) for name, value in item.items())


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TransactGetItems whose addressed items are each under 400 KB but exceed 4 MB in aggregate is
    a ValidationException that returns none of them; the same items minus one stay under 4 MB and
    every one of them comes back whole.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb, "sim2real-behav-ddb-txget4mb-")

    big = [_item(f"big-{i:02d}") for i in range(_OVER_LIMIT_ITEMS)]
    for it in big:
        ddb.put_item(TableName=table, Item=it)

    under = big[:_UNDER_LIMIT_ITEMS]
    under_aggregate = sum(_item_size(it) for it in under)
    assert under_aggregate < 4 * 1024 * 1024, f"the under-limit items total {under_aggregate!r} bytes"
    resp = ddb.transact_get_items(
        TransactItems=[{"Get": {"TableName": table, "Key": {"pk": it["pk"]}}} for it in under]
    )
    responses = [r["Item"] for r in resp["Responses"]]
    assert responses == under, (
        f"a {under_aggregate!r}-byte TransactGetItems returned {len(responses)} item(s), expected {len(under)}"
    )

    aggregate = sum(_item_size(it) for it in big)
    assert aggregate > 4 * 1024 * 1024, f"the over-limit items total only {aggregate!r} bytes"
    code, msg, reasons = _error(lambda: ddb.transact_get_items(
        TransactItems=[{"Get": {"TableName": table, "Key": {"pk": it["pk"]}}} for it in big]))
    assert (code, msg) == _TOO_LARGE, (
        f"a {aggregate!r}-byte TransactGetItems gave {code!r}: {msg!r}"
    )
    assert reasons is None, f"a top-level ValidationException carried CancellationReasons {reasons!r}"

    survivor = big[-1]
    got = ddb.get_item(TableName=table, Key={"pk": survivor["pk"]}, ConsistentRead=True).get("Item")
    assert got == survivor, (
        f"after the refused over-4 MB read, GetItem on {survivor['pk']!r} returned {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
