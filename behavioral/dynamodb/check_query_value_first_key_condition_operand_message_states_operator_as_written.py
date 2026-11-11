"""query-value-first-key-condition-operand-message-states-operator-as-written."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-value-first-key-condition-operand-message-states-operator-as-written"
GROUP = "access_path"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


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
    """A Query key-condition ordering comparison with the value written on the left
    (:v >= sk) reports an operand-type mismatch with the operator exactly as written in
    the expression, not its logical mirror (sk <= :v reads back as '<=', not '>=').
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-qvf-")
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
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    for sk in ("a", "b", "c"):
        ddb.put_item(TableName=table, Item={"pk": {"S": "p"}, "sk": {"S": sk}})

    def query_error(kce):
        return _error(lambda: ddb.query(
            TableName=table, KeyConditionExpression=kce,
            ExpressionAttributeValues={":p": {"S": "p"}, ":v": {"BOOL": True}},
        ))

    # Each pair compares a value-first form against its logical mirror, key-first. A
    # BOOL operand is illegal for every one of these operators regardless of which side
    # it sits on, so the only thing that can differ between the two messages in a pair
    # is which operator token the parser reports — and it reports the one written.
    pairs = (
        ("pk = :p AND :v >= sk", ">=", "pk = :p AND sk <= :v", "<="),
        ("pk = :p AND :v <= sk", "<=", "pk = :p AND sk >= :v", ">="),
        ("pk = :p AND :v > sk", ">", "pk = :p AND sk < :v", "<"),
        ("pk = :p AND :v < sk", "<", "pk = :p AND sk > :v", ">"),
    )
    for value_first_kce, value_first_op, key_first_kce, key_first_op in pairs:
        code, message = query_error(value_first_kce)
        assert code == ERR_VALIDATION, f"{value_first_kce!r}: expected {ERR_VALIDATION}, got {code} ({message!r})"
        expected = _operand_type_mismatch(value_first_op, "BOOL")
        assert message == expected, f"{value_first_kce!r}: expected message {expected!r}, got {message!r}"

        code2, message2 = query_error(key_first_kce)
        assert code2 == ERR_VALIDATION, f"{key_first_kce!r}: expected {ERR_VALIDATION}, got {code2} ({message2!r})"
        expected2 = _operand_type_mismatch(key_first_op, "BOOL")
        assert message2 == expected2, f"{key_first_kce!r}: expected message {expected2!r}, got {message2!r}"

        assert message != message2, (
            f"value-first {value_first_kce!r} and its mirror {key_first_kce!r} reported the same "
            f"message {message!r}; the operator token should differ between them"
        )

    # Positive control: the identical value-first form, correctly typed, still selects the
    # expected range after every rejection above.
    control = ddb.query(
        TableName=table, KeyConditionExpression="pk = :p AND :lo <= sk", ConsistentRead=True,
        ExpressionAttributeValues={":p": {"S": "p"}, ":lo": {"S": "b"}},
    )
    sks = sorted(it["sk"]["S"] for it in control["Items"])
    assert sks == ["b", "c"], f"':lo <= sk' with lo='b' selected {sks!r}, expected ['b', 'c']"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
