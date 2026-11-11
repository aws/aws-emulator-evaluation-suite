"""put-item-condition-nested-document-paths-and-functions-that-hold."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-condition-nested-document-paths-and-functions-that-hold"
GROUP = "conditions"
SERVICES = ["dynamodb"]
_CCF = ("ConditionalCheckFailedException", "The conditional request failed")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """The (Code, Message) fn() raises. Raises when fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c2", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem's ConditionExpression evaluates functions and document paths against the
    existing item: each holding form lets the replacement item apply; a false one fails
    with ConditionalCheckFailedException and leaves the stored item unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-put-cond-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "ddb-put-cond"}}
    base_doc = {
        "m": {"M": {"k": {"S": "inner"}, "n": {"L": [{"N": "10"}, {"S": "ten"}]}}},
        "status": {"S": "active"},
        "tag": {"S": "alpha-needle-beta"},
    }
    ddb.put_item(TableName=table, Item={**key, **base_doc, "seq": {"N": "0"}})

    def read():
        return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")

    def put_holding(seq: int, cond_expr: str, names: dict, values: dict) -> None:
        item = {**key, **base_doc, "seq": {"N": str(seq)}}
        kwargs = {}
        if names:
            kwargs["ExpressionAttributeNames"] = names
        if values:
            kwargs["ExpressionAttributeValues"] = values
        ddb.put_item(TableName=table, Item=item, ConditionExpression=cond_expr, **kwargs)
        got = read()
        assert got == item, f"PutItem under holding condition {cond_expr!r} left {got!r}, expected {item!r}"

    # attribute_exists on a nested map path that is present.
    put_holding(1, "attribute_exists(#m.#k)", {"#m": "m", "#k": "k"}, {})

    # attribute_not_exists on a nested map path that is absent.
    put_holding(2, "attribute_not_exists(#m.#z)", {"#m": "m", "#z": "z"}, {})

    # NOT negates its operand: NOT(false) holds.
    put_holding(3, "NOT (#m.#k = :other)", {"#m": "m", "#k": "k"}, {":other": {"S": "nope"}})

    # Compound AND: both arms true.
    put_holding(
        4, "#m.#k = :inner AND #m.#n[0] = :ten",
        {"#m": "m", "#k": "k", "#n": "n"}, {":inner": {"S": "inner"}, ":ten": {"N": "10"}},
    )

    # OR with one false arm: the second arm is true.
    put_holding(
        5, "#m.#k = :other OR #m.#k = :inner",
        {"#m": "m", "#k": "k"}, {":other": {"S": "other"}, ":inner": {"S": "inner"}},
    )

    # contains(attr, substring) on a top-level string attribute.
    put_holding(6, "contains(#tag, :needle)", {"#tag": "tag"}, {":needle": {"S": "needle"}})

    # A nested map path referenced with plain dot notation, with no ExpressionAttributeNames,
    # because neither "m" nor "k" is a reserved word.
    put_holding(7, "m.k = :inner", {}, {":inner": {"S": "inner"}})

    # A reserved word ("status") used in a condition only once aliased.
    put_holding(8, "#st = :active", {"#st": "status"}, {":active": {"S": "active"}})

    # A near-miss: the nested path compares to a value the item does not hold.
    before = read()
    code, msg = _error(lambda: ddb.put_item(
        TableName=table, Item={**key, **base_doc, "seq": {"N": "9"}},
        ConditionExpression="#m.#k = :other", ExpressionAttributeNames={"#m": "m", "#k": "k"},
        ExpressionAttributeValues={":other": {"S": "other"}},
    ))
    assert (code, msg) == _CCF, f"PutItem under a failing nested condition gave {code!r}: {msg!r}"
    after = read()
    assert after == before, f"PutItem under a failing nested condition left {after!r}, expected {before!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
