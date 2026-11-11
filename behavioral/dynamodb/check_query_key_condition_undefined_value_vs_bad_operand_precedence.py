"""query-key-condition-undefined-value-vs-bad-operand-precedence."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-key-condition-undefined-value-vs-bad-operand-precedence"
GROUP = "access_path"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"
ERR_NOT_FOUND = "ResourceNotFoundException"

_UNDEFINED_VALUE = (
    "Invalid KeyConditionExpression: An expression attribute value used in expression is not "
    "defined; attribute value: :undef"
)
_BAD_OPERAND = (
    "Invalid KeyConditionExpression: Incorrect operand type for operator or function; "
    "operator or function: begins_with, operand type: N"
)
_THIRD_CONDITION = (
    "The number of query conditions (3) exceeds the number of key attributes defined in the "
    "schema (2)"
)


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
    """A KeyConditionExpression's undefined placeholder and its wrong-typed begins_with operand
    are reported in the order they are written; the operand error alone still beats a third
    ANDed clause and a missing table.
    """
    ddb = ctx.client("dynamodb")
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
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={"pk": {"S": "x"}, "sk": {"S": "y"}, "extra": {"S": "z"}})

    # Positive control: the plain two-clause form the cases below are variations of.
    control = ddb.query(
        TableName=table, KeyConditionExpression="pk = :pk AND sk = :sk",
        ExpressionAttributeValues={":pk": {"S": "x"}, ":sk": {"S": "y"}},
    )
    assert control["Count"] == 1, f"positive control: expected the one put item, got {control['Count']}"

    # Order A: the undefined placeholder (:undef, in the pk clause) is written before the
    # wrong-typed begins_with operand (:bad, defined but N where the sort key is S).
    code, message = _error(lambda: ddb.query(
        TableName=table, KeyConditionExpression="pk = :undef AND begins_with(sk, :bad)",
        ExpressionAttributeValues={":bad": {"N": "1"}},
    ))
    assert code == ERR_VALIDATION, f"order A (undefined first): expected {ERR_VALIDATION}, got {code} ({message!r})"
    assert message == _UNDEFINED_VALUE, f"order A (undefined first): expected {_UNDEFINED_VALUE!r}, got {message!r}"

    # Order B: the identical two defects, with the begins_with clause written first.
    code, message = _error(lambda: ddb.query(
        TableName=table, KeyConditionExpression="begins_with(sk, :bad) AND pk = :undef",
        ExpressionAttributeValues={":bad": {"N": "1"}},
    ))
    assert code == ERR_VALIDATION, f"order B (operand first): expected {ERR_VALIDATION}, got {code} ({message!r})"
    assert message == _BAD_OPERAND, f"order B (operand first): expected {_BAD_OPERAND!r}, got {message!r}"

    # The wrong-typed operand alone (every placeholder defined) still beats a third ANDed
    # clause naming a real, non-key attribute.
    code, message = _error(lambda: ddb.query(
        TableName=table,
        KeyConditionExpression="pk = :pk AND begins_with(sk, :bad) AND extra = :extra",
        ExpressionAttributeValues={":pk": {"S": "x"}, ":bad": {"N": "1"}, ":extra": {"S": "z"}},
    ))
    assert code == ERR_VALIDATION, f"operand vs third clause: expected {ERR_VALIDATION}, got {code} ({message!r})"
    assert message == _BAD_OPERAND, f"operand vs third clause: expected {_BAD_OPERAND!r}, got {message!r}"

    # Confirm the third-clause message itself still exists on this table when the operand is
    # well-typed, so the case above is shown to be about the operand, not about this table
    # tolerating a third clause.
    code, message = _error(lambda: ddb.query(
        TableName=table,
        KeyConditionExpression="pk = :pk AND sk = :sk AND extra = :extra",
        ExpressionAttributeValues={":pk": {"S": "x"}, ":sk": {"S": "y"}, ":extra": {"S": "z"}},
    ))
    assert code == ERR_VALIDATION, f"well-typed third clause: expected {ERR_VALIDATION}, got {code} ({message!r})"
    assert message == _THIRD_CONDITION, f"well-typed third clause: expected {_THIRD_CONDITION!r}, got {message!r}"

    # The wrong-typed operand alone (no undefined placeholder, no third clause) still beats a
    # missing table.
    absent = ctx.unique_name("sim2real-behav-absent-")
    code, message = _error(lambda: ddb.query(
        TableName=absent, KeyConditionExpression="pk = :pk AND begins_with(sk, :bad)",
        ExpressionAttributeValues={":pk": {"S": "x"}, ":bad": {"N": "1"}},
    ))
    assert code == ERR_VALIDATION, f"operand vs missing table: expected {ERR_VALIDATION}, got {code} ({message!r})"
    assert message == _BAD_OPERAND, f"operand vs missing table: expected {_BAD_OPERAND!r}, got {message!r}"

    # Baseline: the well-formed form against that same absent table name is the existence error.
    code, message = _error(lambda: ddb.query(
        TableName=absent, KeyConditionExpression="pk = :pk AND sk = :sk",
        ExpressionAttributeValues={":pk": {"S": "x"}, ":sk": {"S": "y"}},
    ))
    assert code == ERR_NOT_FOUND, f"well-formed call against missing table: expected {ERR_NOT_FOUND}, got {code} ({message!r})"
    assert message == "Requested resource not found", (
        f"well-formed call against missing table: expected message, got {message!r}"
    )

    # Final control: the real table still answers correctly after every rejection above.
    final = ddb.query(
        TableName=table, KeyConditionExpression="pk = :pk AND sk = :sk",
        ExpressionAttributeValues={":pk": {"S": "x"}, ":sk": {"S": "y"}},
    )
    assert final["Count"] == 1, f"final control: expected the one put item, got {final['Count']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
