"""query-key-condition-non-key-missing-partition-begins-with-partition-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-key-condition-non-key-missing-partition-begins-with-partition-rejected"
GROUP = "query"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error(fn) -> tuple:
    """The (code, message) of the ClientError fn() raises. RAISES when fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A KeyConditionExpression naming a non-key attribute, omitting the partition key, or using
    begins_with on the partition key is rejected with its own exact message; legal Queries work.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-qkc-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for sk, extra in (("a", "1"), ("b", "2")):
        ddb.put_item(TableName=table, Item={"pk": {"S": "p"}, "sk": {"S": sk}, "extra": {"S": extra}})

    # (1) `extra` is a real attribute on every item but is not part of any key schema; it is
    # ANDed onto a correct partition-key condition so the rejection is attributable to `extra`
    # standing in for the sort key, not to a missing partition key (case 2, below).
    code, message = _error(lambda: ddb.query(
        TableName=table, KeyConditionExpression="pk = :p AND extra = :v",
        ExpressionAttributeValues={":p": {"S": "p"}, ":v": {"S": "1"}},
    ))
    assert code == ERR_VALIDATION, f"non-key attribute in KeyConditionExpression answered {code!r} ({message!r})"
    expected_nonkey = "Query condition missed key schema element: sk"
    assert message == expected_nonkey, f"expected message {expected_nonkey!r}, got {message!r}"

    # (2) The partition key `pk` is never mentioned; only the sort key is.
    code, message = _error(lambda: ddb.query(
        TableName=table, KeyConditionExpression="sk = :v",
        ExpressionAttributeValues={":v": {"S": "a"}},
    ))
    assert code == ERR_VALIDATION, f"missing partition key in KeyConditionExpression answered {code!r} ({message!r})"
    expected_missing_pk = "Query condition missed key schema element: pk"
    assert message == expected_missing_pk, f"expected message {expected_missing_pk!r}, got {message!r}"

    # Query legally in between the two remaining malformations, to show neither rejection left
    # the table or the access path broken.
    control = ddb.query(
        TableName=table, KeyConditionExpression="pk = :p",
        ExpressionAttributeValues={":p": {"S": "p"}}, ConsistentRead=True,
    )
    assert control["Count"] == 2, f"legal Query mid-sequence matched {control['Count']!r}, expected 2"

    # (3) `begins_with` is legal on a sort key, never on the partition key.
    code, message = _error(lambda: ddb.query(
        TableName=table, KeyConditionExpression="begins_with(pk, :v)",
        ExpressionAttributeValues={":v": {"S": "p"}},
    ))
    assert code == ERR_VALIDATION, f"begins_with on the partition key answered {code!r} ({message!r})"
    expected_begins_with_pk = "Query key condition not supported"
    assert message == expected_begins_with_pk, f"expected message {expected_begins_with_pk!r}, got {message!r}"

    # Positive control: the legal form -- partition key equality ANDed with begins_with on the
    # sort key -- still works after all three rejections.
    final = ddb.query(
        TableName=table, KeyConditionExpression="pk = :p AND begins_with(sk, :s)",
        ExpressionAttributeValues={":p": {"S": "p"}, ":s": {"S": "a"}}, ConsistentRead=True,
    )
    got = sorted(i["sk"]["S"] for i in final["Items"])
    assert got == ["a"], f"begins_with on the sort key returned sk values {got!r}, expected ['a']"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
