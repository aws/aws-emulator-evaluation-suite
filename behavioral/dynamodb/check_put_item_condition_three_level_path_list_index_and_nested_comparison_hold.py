"""put-item-condition-three-level-path-list-index-and-nested-comparison-hold."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-condition-three-level-path-list-index-and-nested-comparison-hold"
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
    """PutItem's ConditionExpression evaluates a three-level nested map path, a list index
    then an aliased map child, a top-level list element and a nested numeric comparison
    against the existing item; each holding form lets the write apply.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-put-cond3-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "ddb-put-cond3"}}
    base_doc = {
        "m": {"M": {
            "mm": {"M": {"k": {"S": "deep"}}},
            "n": {"L": [{"N": "42"}, {"N": "7"}]},
        }},
        "l": {"L": [{"M": {"k": {"S": "first"}}}, {"S": "second"}]},
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

    # Three-level nested map path equality: m -> mm -> k.
    put_holding(1, "#m.#mm.#k = :deep", {"#m": "m", "#mm": "mm", "#k": "k"}, {":deep": {"S": "deep"}})

    # List index then an aliased map child: l[0] is a map, then its "k" member.
    put_holding(2, "#l[0].#k = :first", {"#l": "l", "#k": "k"}, {":first": {"S": "first"}})

    # Top-level list index element equality against a scalar.
    put_holding(3, "#l[1] = :second", {"#l": "l"}, {":second": {"S": "second"}})

    # Nested number comparison: m.n[0] (42) >= 40.
    put_holding(4, "#m.#n[0] >= :threshold", {"#m": "m", "#n": "n"}, {":threshold": {"N": "40"}})

    # A near-miss: the nested numeric comparison does not hold against the stored value.
    before = read()
    code, msg = _error(lambda: ddb.put_item(
        TableName=table, Item={**key, **base_doc, "seq": {"N": "9"}},
        ConditionExpression="#m.#n[0] >= :toohigh", ExpressionAttributeNames={"#m": "m", "#n": "n"},
        ExpressionAttributeValues={":toohigh": {"N": "100"}},
    ))
    assert (code, msg) == _CCF, f"PutItem under a failing nested comparison gave {code!r}: {msg!r}"
    after = read()
    assert after == before, f"PutItem under a failing nested comparison left {after!r}, expected {before!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
