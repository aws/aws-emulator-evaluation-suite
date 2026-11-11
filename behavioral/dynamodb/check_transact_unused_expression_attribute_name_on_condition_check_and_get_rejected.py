"""transact-unused-expression-attribute-name-on-condition-check-and-get-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-unused-expression-attribute-name-on-condition-check-and-get-rejected"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_UNUSED_NAME = "Value provided in ExpressionAttributeNames unused in expressions: keys: {#n}"


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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An unused ExpressionAttributeNames entry on a ConditionCheck or a projected Get is a
    top-level ValidationException; the transaction writes nothing and the used form succeeds.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ExpressionAttributeNames.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb, "sim2real-behav-ddb-txun-")
    seed = {"pk": {"S": "seed"}, "color": {"S": "red"}}
    ddb.put_item(TableName=table, Item=seed)
    new_key = {"pk": {"S": "new"}}

    def write(names):
        return ddb.transact_write_items(TransactItems=[
            {"ConditionCheck": {
                "TableName": table, "Key": {"pk": {"S": "seed"}},
                "ConditionExpression": "attribute_exists(pk)", "ExpressionAttributeNames": names,
            }},
            {"Put": {"TableName": table, "Item": {**new_key, "v": {"S": "1"}}}},
        ])

    code, msg, reasons = _error(lambda: write({"#n": "color"}))
    assert (code, msg) == ("ValidationException", _UNUSED_NAME), (
        f"ConditionCheck with an unused name gave {code!r}: {msg!r}"
    )
    assert reasons is None, f"a top-level ValidationException carried CancellationReasons {reasons!r}"
    assert _get(ddb, table, new_key) is None, "a refused transaction wrote its Put"

    def read(projection, names):
        return ddb.transact_get_items(TransactItems=[{"Get": {
            "TableName": table, "Key": {"pk": {"S": "seed"}},
            "ProjectionExpression": projection, "ExpressionAttributeNames": names,
        }}])

    code, msg, reasons = _error(lambda: read("pk", {"#n": "color"}))
    assert (code, msg) == ("ValidationException", _UNUSED_NAME), (
        f"TransactGetItems Get with an unused name gave {code!r}: {msg!r}"
    )
    assert reasons is None, f"a top-level ValidationException carried CancellationReasons {reasons!r}"

    resp = read("#n", {"#n": "color"})
    assert resp["Responses"] == [{"Item": {"color": {"S": "red"}}}], (
        f"TransactGetItems projecting #n=color returned {resp['Responses']!r}"
    )
    ddb.transact_write_items(TransactItems=[
        {"ConditionCheck": {
            "TableName": table, "Key": {"pk": {"S": "seed"}},
            "ConditionExpression": "attribute_exists(#n)", "ExpressionAttributeNames": {"#n": "color"},
        }},
        {"Put": {"TableName": table, "Item": {**new_key, "v": {"S": "1"}}}},
    ])
    got = _get(ddb, table, new_key)
    assert got == {**new_key, "v": {"S": "1"}}, f"the transaction with every name used stored {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
