"""execute-statement-quoting-rules."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-quoting-rules"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _error_code_and_message(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails,
    naming what came back rather than turning an over-permissive accept into a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected ExecuteStatement to be rejected, but it SUCCEEDED with {result!r}")


def _wait_for_table_active(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never went ACTIVE in {timeout_s}s (last={status})")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement rejects a single-quoted table name and an unquoted reserved keyword
    attribute with ValidationException, each leaving the table unwritten, while a double-quoted
    string literal is ACCEPTED as a path reference rather than a value and matches nothing.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.html
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-quote-")
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
        Tags=_TAGS_KV,
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_for_table_active(ddb, table_name)

    seed_key = {"pk": {"S": "seed-pk"}, "sk": {"S": "seed-sk"}}
    ddb.put_item(TableName=table_name, Item={**seed_key, "note": {"S": "orig"}})

    # Case A: the table name in single quotes is rejected; nothing is written.
    code, message = _error_code_and_message(
        lambda: ddb.execute_statement(
            Statement=f"INSERT INTO '{table_name}' VALUE {{'pk':'single-quoted-tbl','sk':'s1'}}"
        )
    )
    assert code == "ValidationException", f"single-quoted table name: expected ValidationException, got {code!r}"
    expected_a = "Statement wasn't well formed, can't be processed: Expected identifier for simple path"
    assert message == expected_a, f"single-quoted table name: expected message {expected_a!r}, got {message!r}"
    unwritten_a = ddb.get_item(
        TableName=table_name, Key={"pk": {"S": "single-quoted-tbl"}, "sk": {"S": "s1"}}, ConsistentRead=True
    )
    assert "Item" not in unwritten_a, f"single-quoted table name: expected no write, got {unwritten_a.get('Item')!r}"

    # Case B: an unquoted reserved keyword ('size') as an attribute name is rejected; nothing written.
    code, message = _error_code_and_message(
        lambda: ddb.execute_statement(
            Statement=f"INSERT INTO \"{table_name}\" VALUE {{'pk':'reserved-attr','sk':'s1', size:'x'}}"
        )
    )
    assert code == "ValidationException", f"unquoted reserved attribute: expected ValidationException, got {code!r}"
    expected_b = "Statement wasn't well formed, can't be processed: Unexpected keyword"
    assert message == expected_b, f"unquoted reserved attribute: expected message {expected_b!r}, got {message!r}"
    unwritten_b = ddb.get_item(
        TableName=table_name, Key={"pk": {"S": "reserved-attr"}, "sk": {"S": "s1"}}, ConsistentRead=True
    )
    assert "Item" not in unwritten_b, f"unquoted reserved attribute: expected no write, got {unwritten_b.get('Item')!r}"

    # Case C: a string literal in double quotes is ACCEPTED, because double quotes denote a path
    # reference rather than a string value, so the comparison matches nothing.
    accepted = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table_name}" WHERE pk = "seed-pk" AND sk = "seed-sk"'
    )
    assert accepted["Items"] == [], (
        f"double-quoted literal: expected the path-reference comparison to match nothing, "
        f"got {accepted['Items']!r}"
    )

    # Positive control: the identical comparison written with single-quoted string literals
    # matches the seed item, proving Case C's empty result is the quoting, not a broken table.
    control = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table_name}\" WHERE pk = 'seed-pk' AND sk = 'seed-sk'"
    )
    assert control["Items"] == [{**seed_key, "note": {"S": "orig"}}], (
        f"positive control: expected the seed item back, got {control['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
