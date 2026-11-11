"""query-filter-expression-undefined-value-rejected-over-a-1mb-partition."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-filter-expression-undefined-value-rejected-over-a-1mb-partition"
GROUP = "errors"
SERVICES = ["dynamodb"]

_ITEM_BYTES = 50 * 1024
_ITEM_COUNT = 40


def _error(fn) -> tuple:
    """The (code, message) ``fn`` is refused with. An unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An undefined expression attribute value in Query's FilterExpression is a ValidationException
    even over a partition exceeding the 1 MB page limit, so the expression is parsed before any
    page is produced rather than failing only once the budget is reached.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddb-qfundef-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    payload = "x" * _ITEM_BYTES
    for i in range(_ITEM_COUNT):
        ddb.put_item(TableName=t, Item={"pk": {"S": "big"}, "sk": {"S": f"{i:03d}"}, "payload": {"S": payload}})

    base = {
        "TableName": t,
        "KeyConditionExpression": "pk = :p",
        "ExpressionAttributeValues": {":p": {"S": "big"}},
        "ConsistentRead": True,
    }

    # Positive control: a well-formed never-matching filter over the same > 1 MB partition
    # truncates normally, proving the partition is large enough for the budget to apply at all.
    control = ddb.query(**base, FilterExpression="attribute_exists(no_such_attr)")
    assert control["Count"] == 0 and control["Items"] == [], (
        f"control filter must match nothing, got Count={control['Count']} Items={control['Items']!r}"
    )
    assert "LastEvaluatedKey" in control, (
        "the control page must be truncated by the 1 MB budget and carry a LastEvaluatedKey"
    )

    # The broken call: FilterExpression names :missing_tag, never defined in
    # ExpressionAttributeValues, over the same > 1 MB partition.
    code, message = _error(lambda: ddb.query(
        **base, FilterExpression="tag = :missing_tag",
    ))
    assert code == "ValidationException", (
        f"an undefined expression attribute value in FilterExpression over a > 1 MB partition "
        f"gave {code!r}, expected ValidationException"
    )
    expected = (
        "Invalid FilterExpression: An expression attribute value used in expression is not "
        "defined; attribute value: :missing_tag"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
