"""transact-items-accept-placeholders-without-an-expression."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-items-accept-placeholders-without-an-expression"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_EAN_NO_EXPR_PUTITEM = (
    "1 validation error detected: ExpressionAttributeNames can only be specified when using expressions"
)
_EAV_NO_EXPR_PUTITEM = (
    "1 validation error detected: ExpressionAttributeValues can only be specified when using expressions"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TransactWriteItems Put/Delete and TransactGetItems Get carrying placeholders without any
    expression are accepted and applied, while PutItem refuses the same placeholders.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb, "sim2real-behav-ddb-txph-")
    names = {"#n": "color"}
    values = {":v": {"S": "red"}}

    code, msg, _ = _error(lambda: ddb.put_item(
        TableName=table, Item={"pk": {"S": "single"}}, ExpressionAttributeNames=names,
    ))
    assert (code, msg) == ("ValidationException", _EAN_NO_EXPR_PUTITEM), (
        f"PutItem with ExpressionAttributeNames and no expression gave {code!r}: {msg!r}"
    )
    assert _get(ddb, table, {"pk": {"S": "single"}}) is None, "a refused PutItem wrote its item"
    code, msg, _ = _error(lambda: ddb.put_item(
        TableName=table, Item={"pk": {"S": "single-values"}}, ExpressionAttributeValues=values,
    ))
    assert (code, msg) == ("ValidationException", _EAV_NO_EXPR_PUTITEM), (
        f"PutItem with ExpressionAttributeValues and no expression gave {code!r}: {msg!r}"
    )
    stored = _get(ddb, table, {"pk": {"S": "single-values"}})
    assert stored is None, f"a refused PutItem wrote {stored!r}"

    puts = {"put-names": {"ExpressionAttributeNames": names},
            "put-values": {"ExpressionAttributeValues": values}}
    for pk, extra in puts.items():
        item = {"pk": {"S": pk}, "color": {"S": "blue"}}
        ddb.transact_write_items(TransactItems=[{"Put": {"TableName": table, "Item": item, **extra}}])
        got = _get(ddb, table, {"pk": {"S": pk}})
        assert got == item, f"transactional Put with {sorted(extra)!r} and no expression stored {got!r}"

    deletes = {"put-names": {"ExpressionAttributeNames": names},
               "put-values": {"ExpressionAttributeValues": values}}
    for pk, extra in deletes.items():
        key = {"pk": {"S": pk}}
        ddb.transact_write_items(TransactItems=[{"Delete": {"TableName": table, "Key": key, **extra}}])
        got = _get(ddb, table, key)
        assert got is None, f"transactional Delete with {sorted(extra)!r} and no expression left {got!r}"

    full = {"pk": {"S": "read"}, "color": {"S": "green"}, "size": {"N": "3"}}
    ddb.put_item(TableName=table, Item=full)
    resp = ddb.transact_get_items(TransactItems=[{"Get": {
        "TableName": table, "Key": {"pk": {"S": "read"}}, "ExpressionAttributeNames": names,
    }}])
    assert resp["Responses"] == [{"Item": full}], (
        f"TransactGetItems Get with ExpressionAttributeNames and no projection returned "
        f"{resp['Responses']!r}, expected the full item {full!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
