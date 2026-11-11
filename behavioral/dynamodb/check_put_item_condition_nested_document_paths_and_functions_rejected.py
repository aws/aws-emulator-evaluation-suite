"""put-item-condition-nested-document-paths-and-functions-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-condition-nested-document-paths-and-functions-rejected"
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
    """PutItem's ConditionExpression evaluating a function or document path to false against
    the existing item is ConditionalCheckFailedException and never replaces the item; a
    holding condition on the same item still applies.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-put-cond-neg-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "ddb-put-cond-neg"}}
    original = {
        **key,
        "m": {"M": {"k": {"S": "inner"}, "n": {"L": [{"N": "10"}, {"S": "ten"}]}}},
        "tag": {"S": "alpha-needle-beta"},
    }
    ddb.put_item(TableName=table, Item=original)

    def read():
        return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")

    def rejected(cond_expr: str, names: dict, values: dict) -> None:
        kwargs = {}
        if names:
            kwargs["ExpressionAttributeNames"] = names
        if values:
            kwargs["ExpressionAttributeValues"] = values
        code, msg = _error(lambda: ddb.put_item(
            TableName=table, Item={**key, "overwritten": {"BOOL": True}},
            ConditionExpression=cond_expr, **kwargs,
        ))
        assert (code, msg) == _CCF, f"PutItem under {cond_expr!r} gave {code!r}: {msg!r}"
        got = read()
        assert got == original, f"PutItem under failing {cond_expr!r} left {got!r}, expected {original!r}"

    # attribute_exists on a nested map path that is absent.
    rejected("attribute_exists(#m.#z)", {"#m": "m", "#z": "z"}, {})

    # attribute_not_exists on a nested map path that is present.
    rejected("attribute_not_exists(#m.#k)", {"#m": "m", "#k": "k"}, {})

    # Compound AND: the second arm is false.
    rejected(
        "#m.#k = :inner AND #m.#n[0] = :wrong",
        {"#m": "m", "#k": "k", "#n": "n"}, {":inner": {"S": "inner"}, ":wrong": {"N": "11"}},
    )

    # OR with both arms false.
    rejected(
        "#m.#k = :a OR #m.#k = :b",
        {"#m": "m", "#k": "k"}, {":a": {"S": "a"}, ":b": {"S": "b"}},
    )

    # NOT negates a true operand to false.
    rejected("NOT (#m.#k = :inner)", {"#m": "m", "#k": "k"}, {":inner": {"S": "inner"}})

    # contains(attr, substring) where the substring is absent.
    rejected("contains(#tag, :missing)", {"#tag": "tag"}, {":missing": {"S": "missing"}})

    # A nested path value compared against a different type: the comparison is false, not an error.
    rejected("#m.#k = :num", {"#m": "m", "#k": "k"}, {":num": {"N": "5"}})

    # Positive control: the same mechanism applies the write once the condition holds.
    replacement = {**key, "replaced": {"BOOL": True}}
    ddb.put_item(TableName=table, Item=replacement, ConditionExpression="attribute_exists(#m.#k)",
                ExpressionAttributeNames={"#m": "m", "#k": "k"})
    got = read()
    assert got == replacement, f"the holding control left {got!r}, expected {replacement!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
