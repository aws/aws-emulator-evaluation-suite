"""transact-write-aggregate-size-over-4mb-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-aggregate-size-over-4mb-rejected"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_FILLER_BYTES = 390 * 1024
_OVER_LIMIT_ITEMS = 11
_TOO_LARGE_TEMPLATE = "Transaction payload size cannot exceed 4MB. Payload Size: {size}"


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


def _create_table(ctx, ddb, prefix, range_type=None):
    """Create an on-demand table keyed pk (S), plus sk of range_type when given; wait ACTIVE."""
    table = ctx.unique_name(prefix)
    keys = [{"AttributeName": "pk", "KeyType": "HASH"}]
    attrs = [{"AttributeName": "pk", "AttributeType": "S"}]
    if range_type:
        keys.append({"AttributeName": "sk", "KeyType": "RANGE"})
        attrs.append({"AttributeName": "sk", "AttributeType": range_type})
    ddb.create_table(
        TableName=table, KeySchema=keys, AttributeDefinitions=attrs, BillingMode="PAY_PER_REQUEST",
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


def _get(ddb, table, key):
    """The item at key read with ConsistentRead, or None."""
    return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")


def _item(pk):
    """An item of one short key and one ~390 KB string attribute."""
    return {"pk": {"S": pk}, "data": {"S": "x" * _FILLER_BYTES}}


def _item_size(item):
    """The DynamoDB size of an all-string item: attribute-name bytes plus value bytes."""
    return sum(len(name.encode()) + len(value["S"].encode()) for name, value in item.items())


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TransactWriteItems whose items are each under 400 KB but exceed 4 MB in aggregate is a
    ValidationException that writes none of them; two of the same items then commit in one transaction.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb, "sim2real-behav-ddb-tx4mb-")

    control = [_item(f"ok-{i:02d}") for i in range(2)]
    ddb.transact_write_items(TransactItems=[{"Put": {"TableName": table, "Item": it}} for it in control])
    for it in control:
        got = _get(ddb, table, {"pk": it["pk"]})
        assert got == it, (
            f"control item {it['pk']!r} read back with data length "
            f"{len((got or {}).get('data', {}).get('S', ''))!r}, expected {_FILLER_BYTES!r}"
        )

    big = [_item(f"big-{i:02d}") for i in range(_OVER_LIMIT_ITEMS)]
    aggregate = sum(_item_size(it) for it in big)
    assert aggregate > 4 * 1024 * 1024, f"the over-limit items total only {aggregate!r} bytes"
    expected = _TOO_LARGE_TEMPLATE.format(size=aggregate)
    code, msg, reasons = _error(lambda: ddb.transact_write_items(
        TransactItems=[{"Put": {"TableName": table, "Item": it}} for it in big]))
    assert (code, msg) == ("ValidationException", expected), (
        f"a {aggregate!r}-byte transaction gave {code!r}: {msg!r}"
    )
    assert reasons is None, f"a top-level ValidationException carried CancellationReasons {reasons!r}"
    landed = [it["pk"]["S"] for it in big if _get(ddb, table, {"pk": it["pk"]}) is not None]
    assert landed == [], f"the refused over-4 MB transaction wrote {landed!r}"

    subset = big[:2]
    ddb.transact_write_items(TransactItems=[{"Put": {"TableName": table, "Item": it}} for it in subset])
    for it in subset:
        got = _get(ddb, table, {"pk": it["pk"]})
        assert got == it, (
            f"refused item {it['pk']!r} committed in a two-item transaction read back with data "
            f"length {len((got or {}).get('data', {}).get('S', ''))!r}, expected {_FILLER_BYTES!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
