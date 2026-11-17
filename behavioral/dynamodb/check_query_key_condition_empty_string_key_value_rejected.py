"""query-key-condition-empty-string-key-value-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-key-condition-empty-string-key-value-rejected"
GROUP = "query"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query refuses a KeyConditionExpression equality test naming an empty string as the
    partition or sort key value, each naming only that key, while a non-empty value still matches."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={"pk": {"S": "p1"}, "sk": {"S": "s1"}})

    expected_pk_message = (
        "One or more parameter values are not valid. The AttributeValue for a key "
        "attribute cannot contain an empty string value. Key: pk"
    )
    code, message = _error(lambda: ddb.query(
        TableName=table, KeyConditionExpression="pk = :v", ExpressionAttributeValues={":v": {"S": ""}},
    ))
    assert code == ERR_VALIDATION, f"an empty-string partition key value must be refused {ERR_VALIDATION}, got {code!r}"
    assert message == expected_pk_message, f"expected the message {expected_pk_message!r}, got {message!r}"

    expected_sk_message = (
        "One or more parameter values are not valid. The AttributeValue for a key "
        "attribute cannot contain an empty string value. Key: sk"
    )
    code, message = _error(lambda: ddb.query(
        TableName=table, KeyConditionExpression="pk = :p AND sk = :v",
        ExpressionAttributeValues={":p": {"S": "p1"}, ":v": {"S": ""}},
    ))
    assert code == ERR_VALIDATION, f"an empty-string sort key value must be refused {ERR_VALIDATION}, got {code!r}"
    assert message == expected_sk_message, f"expected the message {expected_sk_message!r}, got {message!r}"

    resp = ddb.query(TableName=table, ConsistentRead=True,
                      KeyConditionExpression="pk = :p", ExpressionAttributeValues={":p": {"S": "p1"}})
    assert resp["Count"] == 1 and resp["Items"][0]["sk"]["S"] == "s1", (
        f"a non-empty partition key value must still match the seeded item, got {resp['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
