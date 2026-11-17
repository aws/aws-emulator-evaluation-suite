"""get-item-and-query-expression-and-legacy-parameter-mixing-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-item-and-query-expression-and-legacy-parameter-mixing-rejected"
GROUP = "legacy"
SERVICES = ["dynamodb"]

_MIX_GETITEM = (
    "ValidationException",
    "Can not use both expression and non-expression parameters in the same request: "
    "Non-expression parameters: {AttributesToGet} Expression parameters: {ProjectionExpression}",
)
_MIX_QUERY = (
    "ValidationException",
    "Can not use both expression and non-expression parameters in the same request: "
    "Non-expression parameters: {QueryFilter} Expression parameters: {KeyConditionExpression}",
)


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetItem refuses AttributesToGet with ProjectionExpression, and Query refuses QueryFilter
    with KeyConditionExpression, each with ValidationException naming both parameters; the
    single-dialect form of each still works, and the item is unchanged after both refusals.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbmix-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    item1 = {"pk": {"S": "p1"}, "sk": {"S": "s1"}, "a": {"S": "1"}, "flag": {"S": "keep"}}
    item2 = {"pk": {"S": "p1"}, "sk": {"S": "s2"}, "a": {"S": "2"}, "flag": {"S": "drop"}}
    ddb.put_item(TableName=table, Item=item1)
    ddb.put_item(TableName=table, Item=item2)
    key1 = {"pk": {"S": "p1"}, "sk": {"S": "s1"}}

    # GetItem: AttributesToGet and ProjectionExpression together are refused.
    expect_error(
        lambda: ddb.get_item(TableName=table, Key=key1, AttributesToGet=["a"], ProjectionExpression="a"),
        *_MIX_GETITEM,
    )

    # Legal neighbour 1: ProjectionExpression alone projects to exactly {'a'}.
    by_expr = ddb.get_item(TableName=table, Key=key1, ProjectionExpression="a", ConsistentRead=True)
    assert by_expr.get("Item") == {"a": {"S": "1"}}, (
        f"ProjectionExpression alone: expected only {{'a'}}, got {by_expr.get('Item')!r}"
    )

    # Legal neighbour 2: AttributesToGet alone projects to the same exact {'a'}.
    by_legacy = ddb.get_item(TableName=table, Key=key1, AttributesToGet=["a"], ConsistentRead=True)
    assert by_legacy.get("Item") == {"a": {"S": "1"}}, (
        f"AttributesToGet alone: expected only {{'a'}}, got {by_legacy.get('Item')!r}"
    )

    # Query: QueryFilter and KeyConditionExpression together are refused.
    expect_error(
        lambda: ddb.query(
            TableName=table,
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": {"S": "p1"}},
            QueryFilter={"flag": {"ComparisonOperator": "EQ", "AttributeValueList": [{"S": "keep"}]}},
        ),
        *_MIX_QUERY,
    )

    # Legal neighbour: KeyConditionExpression plus FilterExpression, both expression-dialect,
    # narrows the two items sharing pk=p1 down to the one matching the filter.
    filtered = ddb.query(
        TableName=table,
        KeyConditionExpression="pk = :pk",
        FilterExpression="flag = :f",
        ExpressionAttributeValues={":pk": {"S": "p1"}, ":f": {"S": "keep"}},
        ConsistentRead=True,
    )
    assert filtered["Count"] == 1, f"expected exactly 1 matching item, got Count={filtered['Count']!r}"
    assert filtered["Items"] == [item1], f"expected only {item1!r}, got {filtered['Items']!r}"

    # Neither refusal mutated the item: a consistent read shows it exactly as written.
    after = ddb.get_item(TableName=table, Key=key1, ConsistentRead=True)
    assert after.get("Item") == item1, f"expected the item unchanged after both refusals, got {after.get('Item')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
