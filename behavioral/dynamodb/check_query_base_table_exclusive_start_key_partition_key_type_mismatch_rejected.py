"""query-base-table-exclusive-start-key-partition-key-type-mismatch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-base-table-exclusive-start-key-partition-key-type-mismatch-rejected"
GROUP = "pagination"
SERVICES = ["dynamodb"]

_BAD_START_KEY = ("ValidationException", "The provided starting key is invalid")


def _error_pair(fn):
    """The (Code, Message) ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    actual_code, actual_message = _error_pair(fn)
    assert actual_code == code, f"expected error code {code!r}, got {actual_code!r}"
    assert actual_message == message, f"expected error message {message!r}, got {actual_message!r}"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A base-table Query refuses an ExclusiveStartKey whose partition key type differs from the
    schema with ValidationException, and the same Query continued from a real LastEvaluatedKey
    returns exactly the remaining items in order.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    for i in range(3):
        ddb.put_item(TableName=table, Item={"pk": {"S": "p0"}, "sk": {"S": f"s{i}"}})

    first = ddb.query(
        TableName=table, KeyConditionExpression="pk = :p", ExpressionAttributeValues={":p": {"S": "p0"}},
        Limit=1, ConsistentRead=True,
    )
    assert [i["sk"]["S"] for i in first["Items"]] == ["s0"], (
        f"expected the Limit=1 page to hold exactly ['s0'], got {[i['sk']['S'] for i in first['Items']]!r}"
    )
    real_key = first.get("LastEvaluatedKey")
    assert real_key is not None, "expected a LastEvaluatedKey from the Limit=1 page over 3 items"

    expect_error(
        lambda: ddb.query(
            TableName=table, KeyConditionExpression="pk = :p", ExpressionAttributeValues={":p": {"S": "p0"}},
            ExclusiveStartKey={"pk": {"N": "1"}, "sk": {"S": "s0"}},
        ),
        *_BAD_START_KEY,
    )

    continued = ddb.query(
        TableName=table, KeyConditionExpression="pk = :p", ExpressionAttributeValues={":p": {"S": "p0"}},
        ExclusiveStartKey=real_key, ConsistentRead=True,
    )
    continued_sks = [i["sk"]["S"] for i in continued["Items"]]
    assert continued_sks == ["s1", "s2"], (
        f"expected the page continued from the real LastEvaluatedKey to hold exactly ['s1', 's2'], got {continued_sks!r}"
    )
    assert "LastEvaluatedKey" not in continued, (
        f"expected the continued page to exhaust the 3-item partition, got LastEvaluatedKey {continued.get('LastEvaluatedKey')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
