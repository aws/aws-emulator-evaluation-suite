"""query-value-first-range-comparison-on-hash-key-wrong-type."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-value-first-range-comparison-on-hash-key-wrong-type"
GROUP = "access_path"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"

_NOT_SUPPORTED = "Query key condition not supported"
_SCHEMA_TYPE_MISMATCH = (
    "One or more parameter values were invalid: Condition parameter type does not match schema type"
)


def _operand_type_mismatch(operator: str, operand_type: str) -> str:
    return (
        f"Invalid KeyConditionExpression: Incorrect operand type for operator or function; "
        f"operator or function: {operator}, operand type: {operand_type}"
    )


def _error(fn) -> tuple:
    """The AWS error (code, message) ``fn`` raises. Raises when the call SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query range comparison on a hash key is reported as unsupported when its
    operand type matches the key's schema, as a schema-type mismatch for a type the
    operator still accepts, else by operand type with the operator named as written.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-hkvf-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    for pk in ("a", "b", "c"):
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}})

    def query_error(kce, operand):
        return _error(lambda: ddb.query(
            TableName=table, KeyConditionExpression=kce,
            ExpressionAttributeValues={":v": operand},
        ))

    # Each pair is a value-first range comparison against its logical mirror, key-first,
    # both against the HASH key of a table with no sort key.
    pairs = (
        (":v >= pk", ">=", "pk <= :v", "<="),
        (":v <= pk", "<=", "pk >= :v", ">="),
        (":v > pk", ">", "pk < :v", "<"),
        (":v < pk", "<", "pk > :v", ">"),
    )
    for value_first_kce, value_first_op, key_first_kce, key_first_op in pairs:
        # Operand type matches the key's own schema type (S): the operator itself is the
        # only problem, so AWS reports the condition as unsupported rather than citing a
        # type at all, for both the value-first form and its key-first mirror.
        code, message = query_error(value_first_kce, {"S": "x"})
        assert code == ERR_VALIDATION, f"{value_first_kce!r}: expected {ERR_VALIDATION}, got {code} ({message!r})"
        assert message == _NOT_SUPPORTED, f"{value_first_kce!r}: expected message {_NOT_SUPPORTED!r}, got {message!r}"

        code2, message2 = query_error(key_first_kce, {"S": "x"})
        assert code2 == ERR_VALIDATION, f"{key_first_kce!r}: expected {ERR_VALIDATION}, got {code2} ({message2!r})"
        assert message2 == _NOT_SUPPORTED, f"{key_first_kce!r}: expected message {_NOT_SUPPORTED!r}, got {message2!r}"

        # Operand type is N: the operator accepts N for other key types, so AWS reports a
        # schema-type mismatch instead of the unsupported-operator message above, on both
        # the value-first form and its key-first mirror.
        code3, message3 = query_error(value_first_kce, {"N": "1"})
        assert code3 == ERR_VALIDATION, f"{value_first_kce!r}/N: expected {ERR_VALIDATION}, got {code3} ({message3!r})"
        assert message3 == _SCHEMA_TYPE_MISMATCH, (
            f"{value_first_kce!r}/N: expected message {_SCHEMA_TYPE_MISMATCH!r}, got {message3!r}"
        )

        code4, message4 = query_error(key_first_kce, {"N": "1"})
        assert code4 == ERR_VALIDATION, f"{key_first_kce!r}/N: expected {ERR_VALIDATION}, got {code4} ({message4!r})"
        assert message4 == _SCHEMA_TYPE_MISMATCH, (
            f"{key_first_kce!r}/N: expected message {_SCHEMA_TYPE_MISMATCH!r}, got {message4!r}"
        )

        # BOOL is illegal for every one of these operators regardless of which side it
        # sits on, so the operand-type error names the operator exactly as written.
        code5, message5 = query_error(value_first_kce, {"BOOL": True})
        assert code5 == ERR_VALIDATION, f"{value_first_kce!r}/BOOL: expected {ERR_VALIDATION}, got {code5} ({message5!r})"
        expected5 = _operand_type_mismatch(value_first_op, "BOOL")
        assert message5 == expected5, f"{value_first_kce!r}/BOOL: expected message {expected5!r}, got {message5!r}"

        code6, message6 = query_error(key_first_kce, {"BOOL": True})
        assert code6 == ERR_VALIDATION, f"{key_first_kce!r}/BOOL: expected {ERR_VALIDATION}, got {code6} ({message6!r})"
        expected6 = _operand_type_mismatch(key_first_op, "BOOL")
        assert message6 == expected6, f"{key_first_kce!r}/BOOL: expected message {expected6!r}, got {message6!r}"

        assert message5 != message6, (
            f"value-first {value_first_kce!r} and its mirror {key_first_kce!r} reported the same "
            f"BOOL-operand message {message5!r}; the operator token should differ between them"
        )

    # Positive control: an equality key condition on the same hash key still selects the
    # expected item after every rejection above.
    control = ddb.query(
        TableName=table, KeyConditionExpression="pk = :p", ConsistentRead=True,
        ExpressionAttributeValues={":p": {"S": "b"}},
    )
    pks = sorted(it["pk"]["S"] for it in control["Items"])
    assert pks == ["b"], f"'pk = :p' with p='b' selected {pks!r}, expected ['b']"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
