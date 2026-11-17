"""query-filter-begins-with-non-string-binary-operand-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-filter-begins-with-non-string-binary-operand-rejected"
GROUP = "query"
SERVICES = ["dynamodb"]

_INVALID_OPERAND_MESSAGE = (
    "Invalid FilterExpression: Incorrect operand type for operator or function; "
    "operator or function: begins_with, operand type: {op_type}"
)


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; raises if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _ids(items) -> frozenset:
    return frozenset(i["sk"]["S"] for i in items)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query's FilterExpression refuses begins_with() on an N or BOOL operand with
    ValidationException, over a populated partition, without changing what a correctly typed
    filter over the same partition returns.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-ddbqfbwr-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": "alpha-item"}, "attr": {"S": "alphabet"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": "zeta-item"}, "attr": {"S": "zebra"}})

    def _query_begins_with(operand_value: dict) -> dict:
        return ddb.query(
            TableName=t,
            KeyConditionExpression="#pk = :pk",
            FilterExpression="begins_with(#a, :v)",
            ExpressionAttributeNames={"#pk": "pk", "#a": "attr"},
            ExpressionAttributeValues={":pk": {"S": "p1"}, ":v": operand_value},
            ConsistentRead=True,
        )

    code, message = _error(lambda: _query_begins_with({"N": "1"}))
    assert code == "ValidationException", (
        f"begins_with with an N operand answered {code!r} ({message!r}), expected ValidationException"
    )
    assert message == _INVALID_OPERAND_MESSAGE.format(op_type="N"), (
        f"begins_with with an N operand said {message!r}, expected "
        f"{_INVALID_OPERAND_MESSAGE.format(op_type='N')!r}"
    )

    code, message = _error(lambda: _query_begins_with({"BOOL": True}))
    assert code == "ValidationException", (
        f"begins_with with a BOOL operand answered {code!r} ({message!r}), expected ValidationException"
    )
    assert message == _INVALID_OPERAND_MESSAGE.format(op_type="BOOL"), (
        f"begins_with with a BOOL operand said {message!r}, expected "
        f"{_INVALID_OPERAND_MESSAGE.format(op_type='BOOL')!r}"
    )

    # The rejected calls wrote nothing: the partition still holds exactly the two seeded items.
    unfiltered = ddb.query(
        TableName=t, KeyConditionExpression="#pk = :pk",
        ExpressionAttributeNames={"#pk": "pk"}, ExpressionAttributeValues={":pk": {"S": "p1"}},
        ConsistentRead=True,
    )
    assert _ids(unfiltered["Items"]) == frozenset({"alpha-item", "zeta-item"}), (
        f"after the rejected begins_with calls the partition held {_ids(unfiltered['Items'])!r}, "
        f"expected the two seeded items unchanged"
    )

    # Positive control: begins_with over the correctly typed S operand still filters normally.
    matched = _query_begins_with({"S": "alpha"})
    assert _ids(matched["Items"]) == frozenset({"alpha-item"}), (
        f"begins_with(attr, (S)'alpha') matched {_ids(matched['Items'])!r}, expected "
        f"{{'alpha-item'}}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
