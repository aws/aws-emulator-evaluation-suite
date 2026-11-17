"""delete-item-condition-list-nested-ordering-not-in-parenthesized-forms-near-miss-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-condition-list-nested-ordering-not-in-parenthesized-forms-near-miss-rejected"
GROUP = "conditions"
SERVICES = ["dynamodb"]

_CCFE = ("ConditionalCheckFailedException", "The conditional request failed")


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteItem conditions on a list element, a nested numeric path, negated
    attribute_exists and ordering, IN and a parenthesized OR-under-AND each
    reject a near-miss item unchanged and delete a sibling item that matches.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    def stored(key):
        return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")

    def check_pair(label, miss_key, miss_item, hold_key, hold_item, condition, miss_values, hold_values):
        """Put each item, assert the near-miss is refused and stays, then the holding delete lands."""
        ddb.put_item(TableName=table, Item=miss_item)
        miss_kwargs = {"ExpressionAttributeValues": miss_values} if miss_values else {}
        expect_error(
            lambda: ddb.delete_item(TableName=table, Key=miss_key, ConditionExpression=condition,
                                    **miss_kwargs),
            *_CCFE,
        )
        kept = stored(miss_key)
        assert kept == miss_item, (
            f"{label}: near-miss condition must leave the item unchanged, got {kept!r}"
        )

        ddb.put_item(TableName=table, Item=hold_item)
        hold_kwargs = {"ExpressionAttributeValues": hold_values} if hold_values else {}
        ddb.delete_item(TableName=table, Key=hold_key, ConditionExpression=condition, **hold_kwargs)
        gone = stored(hold_key)
        assert gone is None, f"{label}: holding condition must delete the item, got {gone!r}"

    # List element equality: l[0] = :v.
    miss_key = {"pk": {"S": f"{table}-list-miss"}}
    hold_key = {"pk": {"S": f"{table}-list-hold"}}
    l_list = {"L": [{"S": "alpha"}, {"S": "beta"}]}
    check_pair(
        "l[0] = :v",
        miss_key, {**miss_key, "l": l_list},
        hold_key, {**hold_key, "l": l_list},
        "l[0] = :v",
        {":v": {"S": "zzz"}},
        {":v": {"S": "alpha"}},
    )

    # Ordering comparison on a nested number: m.n >= :v.
    miss_key = {"pk": {"S": f"{table}-nested-ge-miss"}}
    hold_key = {"pk": {"S": f"{table}-nested-ge-hold"}}
    m_doc = {"M": {"n": {"N": "10"}}}
    check_pair(
        "m.n >= :v",
        miss_key, {**miss_key, "m": m_doc},
        hold_key, {**hold_key, "m": m_doc},
        "m.n >= :v",
        {":v": {"N": "11"}},
        {":v": {"N": "10"}},
    )

    # NOT attribute_exists on an absent attribute.
    miss_key = {"pk": {"S": f"{table}-not-exists-miss"}}
    hold_key = {"pk": {"S": f"{table}-not-exists-hold"}}
    check_pair(
        "NOT attribute_exists(ghost)",
        miss_key, {**miss_key, "ghost": {"S": "present"}},
        hold_key, {**hold_key},
        "NOT attribute_exists(ghost)",
        None,
        None,
    )

    # Negated ordering comparison: NOT (n < :v) holds when n equals v.
    miss_key = {"pk": {"S": f"{table}-not-lt-miss"}}
    hold_key = {"pk": {"S": f"{table}-not-lt-hold"}}
    check_pair(
        "NOT (n < :v)",
        miss_key, {**miss_key, "n": {"N": "5"}},
        hold_key, {**hold_key, "n": {"N": "5"}},
        "NOT (n < :v)",
        {":v": {"N": "6"}},
        {":v": {"N": "5"}},
    )

    # n IN (list of numbers).
    miss_key = {"pk": {"S": f"{table}-in-miss"}}
    hold_key = {"pk": {"S": f"{table}-in-hold"}}
    check_pair(
        "n IN (:a, :b, :c)",
        miss_key, {**miss_key, "n": {"N": "7"}},
        hold_key, {**hold_key, "n": {"N": "7"}},
        "n IN (:a, :b, :c)",
        {":a": {"N": "1"}, ":b": {"N": "2"}, ":c": {"N": "3"}},
        {":a": {"N": "5"}, ":b": {"N": "7"}, ":c": {"N": "9"}},
    )

    # Parenthesized (A OR B) AND C.
    miss_key = {"pk": {"S": f"{table}-or-and-miss"}}
    hold_key = {"pk": {"S": f"{table}-or-and-hold"}}
    check_pair(
        "(a = :x OR a = :y) AND b = :z",
        miss_key, {**miss_key, "a": {"N": "5"}, "b": {"N": "10"}},
        hold_key, {**hold_key, "a": {"N": "5"}, "b": {"N": "10"}},
        "(a = :x OR a = :y) AND b = :z",
        {":x": {"N": "5"}, ":y": {"N": "99"}, ":z": {"N": "999"}},
        {":x": {"N": "5"}, ":y": {"N": "99"}, ":z": {"N": "10"}},
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
