"""get-item-unaliased-reserved-word-in-a-projection-path-segment-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-item-unaliased-reserved-word-in-a-projection-path-segment-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]


def _error(fn) -> tuple:
    """The (Error.Code, Error.Message) fn() raises. RAISES when fn() unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"the call SUCCEEDED and returned {result!r}; real AWS rejects it")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetItem's ProjectionExpression rejects a reserved word used bare inside a nested path
    segment with ValidationException naming the keyword; aliased, the path resolves to the
    nested value.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbresv-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "rec1"}}
    info_map = {"M": {"status": {"S": "ok"}}}
    ddb.put_item(TableName=table, Item={**key, "info": info_map})

    code, message = _error(lambda: ddb.get_item(
        TableName=table, Key=key, ConsistentRead=True, ProjectionExpression="info.status",
    ))
    assert code == "ValidationException", (
        f"an unaliased reserved word inside a projection path segment raised {code!r}, "
        f"expected 'ValidationException'"
    )
    expected = "Invalid ProjectionExpression: Attribute name is a reserved keyword; reserved keyword: status"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Aliased: the placeholder resolves "status" inside the "info" map without complaint.
    ok = ddb.get_item(TableName=table, Key=key, ConsistentRead=True,
                      ProjectionExpression="info.#s", ExpressionAttributeNames={"#s": "status"})
    assert ok["Item"] == {"info": info_map}, (
        f"aliased PE 'info.#s' returned {ok['Item']!r}, expected the whole info map {{'info': "
        f"{info_map!r}}}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
