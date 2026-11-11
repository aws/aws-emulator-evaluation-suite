"""query-key-condition-operand-type-vs-schema-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-key-condition-operand-type-vs-schema-type-rejected"
GROUP = "access_path"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"

_SCHEMA_TYPE_MISMATCH = (
    "One or more parameter values were invalid: Condition parameter type does not match schema type"
)


def _operand_type_mismatch(operator: str, operand_type: str) -> str:
    return (
        f"Invalid KeyConditionExpression: Incorrect operand type for operator or function; "
        f"operator or function: {operator}, operand type: {operand_type}"
    )


def _error(fn) -> tuple:
    """The AWS error (code, message) fn() raises. Raises when the call SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _make_table(ctx, ddb, sk_type: str) -> str:
    table = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": sk_type},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 30})
    return table


def _operand(operand_type: str):
    return {"S": {"S": "x"}, "N": {"N": "1"}, "BOOL": {"BOOL": True}}[operand_type]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query key-condition operand whose type is illegal for the operator itself is reported as
    an operand-type error; one that is operator-legal but wrong for the key's own schema type is
    reported as a schema-type error instead. Neither case writes anything to the table.
    """
    ddb = ctx.client("dynamodb")
    table_s = _make_table(ctx, ddb, "S")
    table_n = _make_table(ctx, ddb, "N")

    # Positive control per table: the correctly typed form is accepted on an empty table.
    for table, sk_type in ((table_s, "S"), (table_n, "N")):
        control = ddb.query(
            TableName=table, KeyConditionExpression="pk = :p AND sk = :s",
            ExpressionAttributeValues={":p": {"S": "p"}, ":s": _operand(sk_type)},
        )
        assert control["Count"] == 0, (
            f"positive control on the {sk_type} sort-key table: expected 0 items, got "
            f"{control['Count']}"
        )

    def run_cell(table, expr, operand_type, expected_code, expected_message, label):
        code, message = _error(lambda: ddb.query(
            TableName=table, KeyConditionExpression=expr,
            ExpressionAttributeValues={":p": {"S": "p"}, ":v": _operand(operand_type)},
        ))
        assert code == expected_code, f"{label}: expected {expected_code}, got {code} ({message!r})"
        assert message == expected_message, f"{label}: expected message {expected_message!r}, got {message!r}"

    # --- S sort-key table: wrong operand types are N and BOOL ---
    for operator, expr in (
        ("begins_with", "pk = :p AND begins_with(sk, :v)"),
        ("<", "pk = :p AND sk < :v"),
        ("BETWEEN", "pk = :p AND sk BETWEEN :v AND :v"),
        ("=", "pk = :p AND sk = :v"),
    ):
        for operand_type in ("N", "BOOL"):
            is_operator_illegal = (operator == "begins_with" and operand_type == "N") or (
                operator in ("begins_with", "<", "BETWEEN") and operand_type == "BOOL"
            )
            expected_code = ERR_VALIDATION
            expected_message = (
                _operand_type_mismatch(operator, operand_type)
                if is_operator_illegal
                else _SCHEMA_TYPE_MISMATCH
            )
            run_cell(
                table_s, expr, operand_type, expected_code, expected_message,
                f"S-sortkey table, operator={operator}, operand={operand_type}",
            )

    # --- N sort-key table: wrong operand types are S and BOOL ---
    for operator, expr in (
        ("begins_with", "pk = :p AND begins_with(sk, :v)"),
        ("<", "pk = :p AND sk < :v"),
        ("BETWEEN", "pk = :p AND sk BETWEEN :v AND :v"),
        ("=", "pk = :p AND sk = :v"),
    ):
        for operand_type in ("S", "BOOL"):
            is_operator_illegal = operator in ("begins_with", "<", "BETWEEN") and operand_type == "BOOL"
            expected_code = ERR_VALIDATION
            expected_message = (
                _operand_type_mismatch(operator, operand_type)
                if is_operator_illegal
                else _SCHEMA_TYPE_MISMATCH
            )
            run_cell(
                table_n, expr, operand_type, expected_code, expected_message,
                f"N-sortkey table, operator={operator}, operand={operand_type}",
            )

    # Read back: none of the rejected cells, on either table, wrote anything.
    for table in (table_s, table_n):
        final = ddb.scan(TableName=table, ConsistentRead=True)
        assert final["Count"] == 0, (
            f"table {table!r} has {final['Count']} item(s) after only rejected Query calls; "
            f"expected 0"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
