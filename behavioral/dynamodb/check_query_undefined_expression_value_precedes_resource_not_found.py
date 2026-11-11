"""query-undefined-expression-value-precedes-resource-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-undefined-expression-value-precedes-resource-not-found"
GROUP = "errors"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"
ERR_NOT_FOUND = "ResourceNotFoundException"


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
    """A Query naming an absent table is ResourceNotFoundException, but an undefined expression
    attribute value in its KeyConditionExpression is a ValidationException that preempts the
    resource lookup, even alongside a wrong-typed operand and a third ANDed clause.
    """
    ddb = ctx.client("dynamodb")

    # Positive control: a real table answers the same expression shape correctly, so the
    # refusals below are about the absent table and the expression, not the wiring.
    table = ctx.unique_name("sim2real-behav-")
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
    ddb.get_waiter("table_exists").wait(
        TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 60}
    )
    ddb.put_item(TableName=table, Item={"pk": {"S": "x"}, "sk": {"S": "y"}})
    control = ddb.query(
        TableName=table,
        KeyConditionExpression="pk = :pk AND sk = :sk",
        ExpressionAttributeValues={":pk": {"S": "x"}, ":sk": {"S": "y"}},
    )
    assert control["Count"] == 1, f"positive control: expected the one put item, got {control['Count']}"

    absent = ctx.unique_name("sim2real-behav-absent-")

    # Baseline: a well-formed expression against the absent table is ResourceNotFoundException.
    code, message = _error(lambda: ddb.query(
        TableName=absent,
        KeyConditionExpression="pk = :pk AND sk = :sk",
        ExpressionAttributeValues={":pk": {"S": "x"}, ":sk": {"S": "y"}},
    ))
    assert code == ERR_NOT_FOUND, f"a well-formed expression against an absent table gave {code!r}"
    assert message == "Requested resource not found", (
        f"a well-formed expression against an absent table: message {message!r}"
    )

    # A wrong-typed operand (a List where a key condition value must be scalar) plus a third
    # ANDed clause, still against the absent table and with every placeholder defined: the
    # existence check still wins, so neither defect alone preempts it.
    code, message = _error(lambda: ddb.query(
        TableName=absent,
        KeyConditionExpression="pk = :pk AND sk = :sk AND extra = :extra",
        ExpressionAttributeValues={":pk": {"L": [{"S": "x"}]}, ":sk": {"S": "y"}, ":extra": {"S": "z"}},
    ))
    assert code == ERR_NOT_FOUND, (
        f"a wrong-typed operand plus a third clause against an absent table gave {code!r}, "
        f"expected the existence check to still win"
    )
    assert message == "Requested resource not found", (
        f"a wrong-typed operand plus a third clause against an absent table: message {message!r}"
    )

    # The same wrong-typed operand and third clause, but now :extra is never defined in
    # ExpressionAttributeValues: the undefined placeholder is caught during expression parsing,
    # before the table is even looked up, so it is this ValidationException that AWS reports.
    code, message = _error(lambda: ddb.query(
        TableName=absent,
        KeyConditionExpression="pk = :pk AND sk = :sk AND extra = :extra",
        ExpressionAttributeValues={":pk": {"L": [{"S": "x"}]}, ":sk": {"S": "y"}},
    ))
    assert code == ERR_VALIDATION, (
        f"a wrong-typed operand, an undefined placeholder and a third clause against an absent "
        f"table gave {code!r}, expected the undefined placeholder to preempt the existence check"
    )
    expected = (
        "Invalid KeyConditionExpression: An expression attribute value used in expression is not "
        "defined; attribute value: :extra"
    )
    assert message == expected, f"expected the message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
