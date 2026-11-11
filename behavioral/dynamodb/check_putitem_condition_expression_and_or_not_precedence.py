"""putitem-condition-expression-and-or-not-precedence."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "putitem-condition-expression-and-or-not-precedence"
GROUP = "conditions"
SERVICES = ["dynamodb"]

_COND_CHECK_FAILED = ("ConditionalCheckFailedException", "The conditional request failed")


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn`` raises exactly ``(code, message)``. RAISES on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, f"expected error code {code!r}, got {err.get('Code')!r}"
        assert err.get("Message") == message, (
            f"expected message {message!r}, got {err.get('Message')!r}"
        )
        return
    raise AssertionError(f"expected the call to be refused with {code}, but it SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutItem ConditionExpression parses with the filter grammar's precedence: AND binds
    tighter than OR, and NOT binds tighter than AND, not left-to-right or outermost-first.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "precedence"}}
    ddb.put_item(TableName=table, Item={**key, "a": {"N": "5"}, "b": {"N": "10"}, "marker": {"S": "seed"}})

    def read_marker():
        item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
        assert item["a"] == {"N": "5"} and item["b"] == {"N": "10"}, (
            f"a/b must stay 5/10 throughout, got a={item.get('a')!r} b={item.get('b')!r}"
        )
        return item["marker"]["S"]

    def put(marker, cond_expr, values):
        ddb.put_item(
            TableName=table,
            Item={**key, "a": {"N": "5"}, "b": {"N": "10"}, "marker": {"S": marker}},
            ConditionExpression=cond_expr,
            ExpressionAttributeValues=values,
        )

    # AND binds tighter than OR: with A=(a=5) true, B=(a=10) false, C=(b=20) false,
    # the implicit `A OR B AND C` is `A OR (B AND C)` = true OR false = true -- admitted.
    vals_and_or = {":five": {"N": "5"}, ":ten": {"N": "10"}, ":twenty": {"N": "20"}}
    put("op1-and-or-implicit-admitted", "a = :five OR a = :ten AND b = :twenty", vals_and_or)
    assert read_marker() == "op1-and-or-implicit-admitted", (
        "`A OR B AND C` should apply as `A OR (B AND C)` = true OR false = true"
    )

    # The explicit `(A OR B) AND C` = (true OR false) AND false = false -- rejected, and the
    # grouped parse's own effect (op1's marker) stays untouched.
    expect_error(
        lambda: put("op2-grouped-should-not-apply", "(a = :five OR a = :ten) AND b = :twenty", vals_and_or),
        *_COND_CHECK_FAILED,
    )
    assert read_marker() == "op1-and-or-implicit-admitted", (
        "the rejected `(A OR B) AND C` write must not change the item"
    )

    # NOT binds tighter than AND: with D=(a=5) true, E=(b=5) false, the bare
    # `NOT D AND E` parses as `(NOT D) AND E` = false AND false = false -- rejected.
    vals_not_and = {":five": {"N": "5"}}
    expect_error(
        lambda: put("op3-bare-should-not-apply", "NOT a = :five AND b = :five", vals_not_and),
        *_COND_CHECK_FAILED,
    )
    assert read_marker() == "op1-and-or-implicit-admitted", (
        "the rejected bare `NOT D AND E` write must not change the item"
    )

    # The grouped `NOT (D AND E)` = NOT(true AND false) = NOT(false) = true -- admitted, proving
    # the bare form above really took the NOT-before-AND parse and not this one.
    put("op4-grouped-not-and-admitted", "NOT (a = :five AND b = :five)", vals_not_and)
    assert read_marker() == "op4-grouped-not-and-admitted", (
        "`NOT (D AND E)` should apply as NOT(true AND false) = true"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
