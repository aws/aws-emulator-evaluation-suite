"""query-and-put-item-placeholder-and-reserved-word-validation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-and-put-item-placeholder-and-reserved-word-validation"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_PUT_UNUSED_NAME_MSG = (
    "1 validation error detected: Value provided in ExpressionAttributeNames unused in "
    "expressions: keys: {#unused}"
)
_QUERY_UNDEFINED_FILTER_NAME_MSG = (
    "Invalid FilterExpression: An expression attribute name used in the document path is not "
    "defined; attribute name: #undefined"
)
_QUERY_UNUSED_NAME_MSG = "Value provided in ExpressionAttributeNames unused in expressions: keys: {#unused}"
_QUERY_UNUSED_VALUE_MSG = "Value provided in ExpressionAttributeValues unused in expressions: keys: {:unused}"
_QUERY_RESERVED_FILTER_MSG = "Invalid FilterExpression: Attribute name is a reserved keyword; reserved keyword: name"
_QUERY_UNDEFINED_PROJECTION_NAME_MSG = (
    "Invalid ProjectionExpression: An expression attribute name used in the document path is not "
    "defined; attribute name: #u"
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


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query refuses an undefined or unused placeholder, a bare reserved word and (before reading,
    even with no match) an undefined projection name; PutItem refuses an unused name.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ExpressionAttributeNames.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-qph-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    for sk, n in (("1", "5"), ("2", "50")):
        ddb.put_item(TableName=table, Item={"pk": {"S": "p"}, "sk": {"S": sk}, "n": {"N": n},
                                            "name": {"S": f"n{sk}"}})
    pk_value = {":pk": {"S": "p"}}

    # Positive control: the aliased form of every refused Query runs and filters.
    resp = ddb.query(TableName=table, KeyConditionExpression="pk = :pk",
                     FilterExpression="#n > :v AND #nm = :nm",
                     ExpressionAttributeNames={"#n": "n", "#nm": "name"},
                     ExpressionAttributeValues={**pk_value, ":v": {"N": "10"}, ":nm": {"S": "n2"}},
                     ConsistentRead=True)
    got = [i["sk"]["S"] for i in resp["Items"]]
    assert got == ["2"], f"the aliased control Query returned sort keys {got!r}, expected ['2']"

    arms = [
        ("PutItem with an unused name", _PUT_UNUSED_NAME_MSG, lambda: ddb.put_item(
            TableName=table, Item={"pk": {"S": "new"}, "sk": {"S": "1"}},
            ConditionExpression="attribute_not_exists(pk)",
            ExpressionAttributeNames={"#unused": "zzz"})),
        ("Query filter with an undefined name", _QUERY_UNDEFINED_FILTER_NAME_MSG, lambda: ddb.query(
            TableName=table, KeyConditionExpression="pk = :pk", FilterExpression="#undefined > :v",
            ExpressionAttributeValues={**pk_value, ":v": {"N": "10"}})),
        ("Query with an unused name", _QUERY_UNUSED_NAME_MSG, lambda: ddb.query(
            TableName=table, KeyConditionExpression="pk = :pk",
            ExpressionAttributeNames={"#unused": "zzz"}, ExpressionAttributeValues=pk_value)),
        ("Query with an unused value", _QUERY_UNUSED_VALUE_MSG, lambda: ddb.query(
            TableName=table, KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={**pk_value, ":unused": {"S": "x"}})),
        ("Query filter with bare reserved word name", _QUERY_RESERVED_FILTER_MSG, lambda: ddb.query(
            TableName=table, KeyConditionExpression="pk = :pk", FilterExpression="name = :v",
            ExpressionAttributeValues={**pk_value, ":v": {"S": "n1"}})),
        ("zero-match Query projecting a.#u undefined", _QUERY_UNDEFINED_PROJECTION_NAME_MSG, lambda: ddb.query(
            TableName=table, KeyConditionExpression="pk = :pk", ProjectionExpression="a.#u",
            ExpressionAttributeValues={":pk": {"S": "nobody"}})),
    ]
    for label, want, call in arms:
        code, msg = _error(call)
        assert (code, msg) == ("ValidationException", want), f"{label} gave {code!r}: {msg!r}"

    absent = ddb.get_item(TableName=table, Key={"pk": {"S": "new"}, "sk": {"S": "1"}},
                          ConsistentRead=True).get("Item")
    assert absent is None, f"the refused PutItem stored {absent!r}"
    count = ddb.scan(TableName=table, Select="COUNT", ConsistentRead=True)["Count"]
    assert count == 2, f"the table holds {count!r} items after the refusals, expected 2"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
