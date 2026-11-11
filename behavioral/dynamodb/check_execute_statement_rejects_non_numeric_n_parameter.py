"""execute-statement-rejects-non-numeric-n-parameter."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-rejects-non-numeric-n-parameter"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_BAD_VALUES = ["abc", "", "1e", "--1"]


def _expected_message(value: str) -> str:
    """The exact ValidationException message AWS returns for this malformed N value."""
    if value == "":
        return "The parameter cannot be converted to a numeric value"
    return f"The parameter cannot be converted to a numeric value: {value}"


def _error_code_and_message(fn):
    """Call fn(); return the botocore Error.Code and Error.Message if a ClientError is raised.
    An unexpected SUCCESS raises, because an emulator accepting input real AWS refuses must
    read as that, never as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected ExecuteStatement to be rejected, but it SUCCEEDED with {result!r}")


def _wait_for_table_active(ddb, table_name, ctx):
    """Poll DescribeTable until ACTIVE, bounded by the time left in the run."""
    deadline = time.monotonic() + max(1.0, min(90.0, (ctx.time_left() or 90.0) - 10.0))
    status = None
    while time.monotonic() < deadline:
        try:
            status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            status = "PENDING"
        if status == "ACTIVE":
            return status
        time.sleep(1.0)
    raise AssertionError(f"table {table_name} never went ACTIVE (last={status})")


def _create_simple_table(ddb, ctx):
    """Create a pk (S) + sk (S) composite-key table, register teardown, wait ACTIVE."""
    table_name = ctx.unique_name("sim2real-behav-ddb-tbl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_for_table_active(ddb, table_name, ctx)
    return table_name


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement rejects an N parameter that is not a numeric string with
    ValidationException in a WHERE comparison, an INSERT value and an UPDATE SET, and
    never writes or changes the item the statement targeted.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes.Number
    """
    ddb = ctx.client("dynamodb")
    table_name = _create_simple_table(ddb, ctx)

    base_pk, base_sk = "probe-pk", "probe-sk"
    ddb.put_item(
        TableName=table_name,
        Item={"pk": {"S": base_pk}, "sk": {"S": base_sk}, "amt": {"N": "5"}},
    )

    # Positive control: a well-formed numeric parameter succeeds in each of the three
    # contexts below, so a rejection is attributable to the malformed value, not to
    # ExecuteStatement or these statement forms being broken.
    control = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table_name}" WHERE "pk" = ? AND "amt" > ?',
        Parameters=[{"S": base_pk}, {"N": "0"}],
    )
    assert control["Items"], f"positive control WHERE comparison found no items: {control!r}"

    for value in _BAD_VALUES:
        def where_call(v=value):
            return ddb.execute_statement(
                Statement=f'SELECT * FROM "{table_name}" WHERE "pk" = ? AND "amt" > ?',
                Parameters=[{"S": base_pk}, {"N": v}],
            )

        code, message = _error_code_and_message(where_call)
        assert code == "ValidationException", (
            f"WHERE comparison with N={value!r}: expected ValidationException, got {code!r}"
        )
        expected = _expected_message(value)
        assert message == expected, (
            f"WHERE comparison with N={value!r}: expected message {expected!r}, got {message!r}"
        )

    for value in _BAD_VALUES:
        insert_sk = f"insert-sk-{value or 'empty'}"

        def insert_call(v=value, sk=insert_sk):
            return ddb.execute_statement(
                Statement=f'INSERT INTO "{table_name}" VALUE {{\'pk\': ?, \'sk\': ?, \'amt\': ?}}',
                Parameters=[{"S": base_pk}, {"S": sk}, {"N": v}],
            )

        code, message = _error_code_and_message(insert_call)
        assert code == "ValidationException", (
            f"INSERT value with N={value!r}: expected ValidationException, got {code!r}"
        )
        expected = _expected_message(value)
        assert message == expected, (
            f"INSERT value with N={value!r}: expected message {expected!r}, got {message!r}"
        )
        item = ddb.get_item(
            TableName=table_name,
            Key={"pk": {"S": base_pk}, "sk": {"S": insert_sk}},
            ConsistentRead=True,
        ).get("Item")
        assert item is None, (
            f"INSERT value with N={value!r}: item was written despite the rejection: {item!r}"
        )

    for value in _BAD_VALUES:
        def update_call(v=value):
            return ddb.execute_statement(
                Statement=f'UPDATE "{table_name}" SET "amt" = ? WHERE "pk" = ? AND "sk" = ?',
                Parameters=[{"N": v}, {"S": base_pk}, {"S": base_sk}],
            )

        code, message = _error_code_and_message(update_call)
        assert code == "ValidationException", (
            f"UPDATE SET with N={value!r}: expected ValidationException, got {code!r}"
        )
        expected = _expected_message(value)
        assert message == expected, (
            f"UPDATE SET with N={value!r}: expected message {expected!r}, got {message!r}"
        )

    final = ddb.get_item(
        TableName=table_name,
        Key={"pk": {"S": base_pk}, "sk": {"S": base_sk}},
        ConsistentRead=True,
    )["Item"]
    assert final["amt"] == {"N": "5"}, (
        f"UPDATE SET with an invalid N must never change the item, got amt={final['amt']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
