"""transact-wrong-typed-key-cancels-and-empty-put-key-validates."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-wrong-typed-key-cancels-and-empty-put-key-validates"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_CANCELLED = "Transaction cancelled, please refer cancellation reasons for specific reasons [None, ValidationError]"
_KEY_SCHEMA = "The provided key element does not match the schema"
_EMPTY_KEY = (
    "One or more parameter values are not valid. The AttributeValue for a key attribute cannot "
    "contain an empty string value. Key: pk"
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


def _assert_cancelled(label, outcome):
    """Assert outcome is a cancellation with reasons [None, ValidationError(key schema)]."""
    code, msg, reasons = outcome
    assert (code, msg) == ("TransactionCanceledException", _CANCELLED), f"{label} gave {code!r}: {msg!r}"
    got = [(r.get("Code"), r.get("Message")) for r in reasons or []]
    assert got == [("None", None), ("ValidationError", _KEY_SCHEMA)], f"{label} reasons were {reasons!r}"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A wrong-typed key in a Delete, Update or Get slot cancels the transaction with ValidationError;
    an empty-string key in a Put slot is a top-level ValidationException. Nothing is written.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb, "sim2real-behav-ddb-txkey-")
    seed_key = {"pk": {"S": "seed"}}
    seed = {**seed_key, "v": {"S": "orig"}}
    ddb.put_item(TableName=table, Item=seed)
    wrong_key = {"pk": {"N": "1"}}
    fresh_key = {"pk": {"S": "fresh"}}
    update_seed = {"Update": {"TableName": table, "Key": seed_key, "UpdateExpression": "SET v = :v",
                              "ExpressionAttributeValues": {":v": {"S": "changed"}}}}
    put_fresh = {"Put": {"TableName": table, "Item": {**fresh_key, "v": {"S": "1"}}}}

    _assert_cancelled("Delete with an N key on an S-keyed table", _error(lambda: ddb.transact_write_items(
        TransactItems=[update_seed, {"Delete": {"TableName": table, "Key": wrong_key}}])))
    _assert_cancelled("Update with an N key on an S-keyed table", _error(lambda: ddb.transact_write_items(
        TransactItems=[put_fresh, {"Update": {"TableName": table, "Key": wrong_key,
                                              "UpdateExpression": "SET v = :v",
                                              "ExpressionAttributeValues": {":v": {"S": "x"}}}}])))
    _assert_cancelled("Get with an N key on an S-keyed table", _error(lambda: ddb.transact_get_items(
        TransactItems=[{"Get": {"TableName": table, "Key": seed_key}},
                       {"Get": {"TableName": table, "Key": wrong_key}}])))

    code, msg, reasons = _error(lambda: ddb.transact_write_items(TransactItems=[
        update_seed, {"Put": {"TableName": table, "Item": {"pk": {"S": ""}, "v": {"S": "1"}}}},
    ]))
    assert (code, msg) == ("ValidationException", _EMPTY_KEY), f"Put with an empty key gave {code!r}: {msg!r}"
    assert reasons is None, f"a top-level ValidationException carried CancellationReasons {reasons!r}"

    got = _get(ddb, table, seed_key)
    assert got == seed, f"a refused transaction changed the seed item to {got!r}"
    assert _get(ddb, table, fresh_key) is None, "a cancelled transaction wrote its Put"
    count = ddb.scan(TableName=table, ConsistentRead=True)["Count"]
    assert count == 1, f"the table holds {count!r} items after only refused transactions, expected 1"

    ddb.transact_write_items(TransactItems=[update_seed, put_fresh])
    got = _get(ddb, table, seed_key)
    assert got == {**seed_key, "v": {"S": "changed"}}, f"the well-keyed transaction left the seed at {got!r}"
    assert _get(ddb, table, fresh_key) == {**fresh_key, "v": {"S": "1"}}, "the well-keyed Put did not land"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
