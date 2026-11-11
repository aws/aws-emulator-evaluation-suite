"""ddb-numeric-sort-key-magnitude-ceiling-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddb-numeric-sort-key-magnitude-ceiling-rejected"
GROUP = "query"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"

# Documented N range ceiling and one magnitude step past it, mirrored to the negative side.
_MAX_MAGNITUDE = "9.9999999999999999999999999999999999999E+125"
_OVER_MAGNITUDE = "1E+126"
# The canonical decimal string the ceiling is stored as: exponents fold into plain digits.
_MAX_STORED = "9" * 38 + "0" * 88


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem on an N sort key at the documented magnitude ceiling is accepted and visible to
    Query; one magnitude step past it, on either sign, is ValidationException and creates nothing.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "N"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # --- positive control: the documented ceiling itself is accepted as a sort key value ---
    ddb.put_item(TableName=table, Item={"pk": {"S": "k"}, "sk": {"N": _MAX_MAGNITUDE}})
    at_ceiling = ddb.query(
        TableName=table, ConsistentRead=True,
        KeyConditionExpression="pk = :p",
        ExpressionAttributeValues={":p": {"S": "k"}},
    )["Items"]
    assert at_ceiling == [{"pk": {"S": "k"}, "sk": {"N": _MAX_STORED}}], (
        f"the at-ceiling sort key must be visible to Query exactly once as N {_MAX_STORED!r}, "
        f"got {at_ceiling!r}"
    )

    # --- one magnitude step past the positive ceiling is rejected ---
    code, message = _error_code(lambda: ddb.put_item(
        TableName=table, Item={"pk": {"S": "k"}, "sk": {"N": _OVER_MAGNITUDE}},
    ))
    assert code == ERR_VALIDATION, (
        f"a sort key magnitude of {_OVER_MAGNITUDE} is past the documented ceiling and must be "
        f"{ERR_VALIDATION}, got {code}"
    )
    assert message == (
        "1 validation error detected: Number overflow. Attempting to store a number with "
        "magnitude larger than supported range"
    ), f"expected AWS's exact ValidationException message, got {message!r}"

    # --- the negative mirror is rejected the same way ---
    neg_code, neg_message = _error_code(lambda: ddb.put_item(
        TableName=table, Item={"pk": {"S": "k"}, "sk": {"N": "-" + _OVER_MAGNITUDE}},
    ))
    assert neg_code == ERR_VALIDATION, (
        f"a sort key magnitude of -{_OVER_MAGNITUDE} must also be {ERR_VALIDATION}, got {neg_code}"
    )
    assert neg_message == (
        "1 validation error detected: Number overflow. Attempting to store a number with "
        "magnitude larger than supported range"
    ), f"expected AWS's exact ValidationException message, got {neg_message!r}"

    # --- neither rejected write created anything: Query under this partition still sees only
    # the one item the positive control created ---
    after = ddb.query(
        TableName=table, ConsistentRead=True,
        KeyConditionExpression="pk = :p",
        ExpressionAttributeValues={":p": {"S": "k"}},
    )["Items"]
    assert after == [{"pk": {"S": "k"}, "sk": {"N": _MAX_STORED}}], (
        f"a rejected PutItem must not create a sort key entry, Query now sees {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
