"""put-item-condition-three-level-path-list-index-and-nested-comparison-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-condition-three-level-path-list-index-and-nested-comparison-rejected"
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


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem's ConditionExpression evaluating a three-level nested map path, a list index
    then an aliased map child, a top-level list element, or a nested numeric comparison to
    false against the existing item is ConditionalCheckFailedException and the item unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-put-cond3-neg-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "ddb-put-cond3-neg"}}
    original = {
        **key,
        "m": {"M": {
            "mm": {"M": {"k": {"S": "deep"}}},
            "n": {"L": [{"N": "42"}, {"N": "7"}]},
        }},
        "l": {"L": [{"M": {"k": {"S": "first"}}}, {"S": "second"}]},
    }
    ddb.put_item(TableName=table, Item=original)

    def read():
        return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")

    def rejected(cond_expr: str, names: dict, values: dict) -> None:
        code, msg = _error(lambda: ddb.put_item(
            TableName=table, Item={**key, "overwritten": {"BOOL": True}},
            ConditionExpression=cond_expr, ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        ))
        assert (code, msg) == _CCF, f"PutItem under {cond_expr!r} gave {code!r}: {msg!r}"
        got = read()
        assert got == original, f"PutItem under failing {cond_expr!r} left {got!r}, expected {original!r}"

    # Three-level nested map path equality against a different value.
    rejected("#m.#mm.#k = :other", {"#m": "m", "#mm": "mm", "#k": "k"}, {":other": {"S": "other"}})

    # List index then an aliased map child, compared against a different value.
    rejected("#l[0].#k = :other", {"#l": "l", "#k": "k"}, {":other": {"S": "other"}})

    # Top-level list index element against a different scalar.
    rejected("#l[1] = :other", {"#l": "l"}, {":other": {"S": "other"}})

    # Nested number comparison that does not hold: m.n[0] (42) is not >= 100.
    rejected("#m.#n[0] >= :toohigh", {"#m": "m", "#n": "n"}, {":toohigh": {"N": "100"}})

    # Positive control: the same mechanism applies the write once the nested condition holds.
    replacement = {**key, "replaced": {"BOOL": True}}
    ddb.put_item(TableName=table, Item=replacement, ConditionExpression="#m.#mm.#k = :deep",
                ExpressionAttributeNames={"#m": "m", "#mm": "mm", "#k": "k"},
                ExpressionAttributeValues={":deep": {"S": "deep"}})
    got = read()
    assert got == replacement, f"the holding control left {got!r}, expected {replacement!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
