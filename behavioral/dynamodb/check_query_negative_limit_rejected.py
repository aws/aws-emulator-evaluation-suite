"""query-negative-limit-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-negative-limit-rejected"
GROUP = "query"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error(fn):
    """Return (code, message) of the ClientError ``fn`` raises; an accepted call fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query with a negative Limit, sent without client-side validation, raises
    ValidationException with the exact message, while Limit=1 still finds the item.
    """
    ddb = ctx.client("dynamodb")
    ddb_raw = ctx.client("dynamodb", config=Config(parameter_validation=False))
    t = ctx.unique_name("sim2real-behav-ddb-qnl-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=t, Item={"pk": {"S": "k"}})

    code, message = _error(lambda: ddb_raw.query(
        TableName=t, KeyConditionExpression="pk = :p", ExpressionAttributeValues={":p": {"S": "k"}},
        Limit=-1,
    ))
    assert code == ERR_VALIDATION, f"negative Limit: expected {ERR_VALIDATION!r}, got {code!r}: {message!r}"
    assert message == (
        "1 validation error detected: Value at 'Limit' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    ), f"negative Limit: unexpected message {message!r}"

    # Positive control: the same item is still found with a valid Limit.
    resp = ddb.query(
        TableName=t, KeyConditionExpression="pk = :p", ExpressionAttributeValues={":p": {"S": "k"}},
        Limit=1, ConsistentRead=True,
    )
    assert resp["Count"] == 1 and resp["Items"][0]["pk"] == {"S": "k"}, (
        f"Limit=1 must still find the item, got Count={resp['Count']!r} Items={resp['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
