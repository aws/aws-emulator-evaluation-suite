"""update-item-multiple-simultaneous-key-violations-reports-one."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-multiple-simultaneous-key-violations-reports-one"
GROUP = "errors"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error(fn):
    """The Error dict of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this UpdateItem, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single UpdateItem naming two independent key or index-key violations at once is
    refused with one ValidationException, never a merged or either/or message.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-mkv-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gpk", "AttributeType": "S"},
            {"AttributeName": "lsisk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "gsi1",
            "KeySchema": [{"AttributeName": "gpk", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        LocalSecondaryIndexes=[{
            "IndexName": "lsi1",
            "KeySchema": [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "lsisk", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "p1"}, "sk": {"S": "orig-sk"}}
    ddb.put_item(
        TableName=table,
        Item={**key, "gpk": {"S": "g1"}, "lsisk": {"S": "l1"}, "note": {"S": "orig"}},
    )

    # Positive control: an ordinary UpdateItem on this item succeeds.
    ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET note = :v",
        ExpressionAttributeValues={":v": {"S": "updated"}},
    )
    baseline = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert baseline["note"] == {"S": "updated"}, f"positive control failed: {baseline!r}"

    # Scenario 1: a range-key rename and a GSI key type mismatch in the same request.
    err1 = _error(lambda: ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET sk = :newsk, gpk = :badgpk",
        ExpressionAttributeValues={":newsk": {"S": "new-sk"}, ":badgpk": {"N": "9"}},
    ))
    assert err1.get("Code") == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {err1}"
    expected1 = (
        "One or more parameter values were invalid: Cannot update attribute sk. "
        "This attribute is part of the key"
    )
    assert err1.get("Message") == expected1, (
        f"expected message {expected1!r}, got {err1.get('Message')!r}"
    )

    after1 = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after1 == baseline, (
        f"a request rejected for naming two violations must leave the item fully "
        f"unchanged, got {after1!r}"
    )

    # Scenario 2: a GSI key type mismatch and an LSI key type mismatch in the same request.
    err2 = _error(lambda: ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET gpk = :badgpk2, lsisk = :badlsisk",
        ExpressionAttributeValues={":badgpk2": {"N": "1"}, ":badlsisk": {"N": "2"}},
    ))
    assert err2.get("Code") == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {err2}"
    expected2 = (
        "One or more parameter values were invalid: Type mismatch for Index Key gpk "
        "Expected: S Actual: N IndexName: gsi1"
    )
    assert err2.get("Message") == expected2, (
        f"expected message {expected2!r}, got {err2.get('Message')!r}"
    )

    after2 = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after2 == baseline, (
        f"a request rejected for naming two bad index keys must leave the item fully "
        f"unchanged, got {after2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
