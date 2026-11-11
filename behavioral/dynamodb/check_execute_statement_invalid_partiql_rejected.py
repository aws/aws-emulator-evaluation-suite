"""execute-statement-invalid-partiql-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-invalid-partiql-rejected"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _error_code_and_message(fn):
    """Call fn(); return the botocore Error.Code and Error.Message if a ClientError is raised. An
    unexpected SUCCESS raises, because an emulator ACCEPTING syntax real AWS refuses is the
    strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected ExecuteStatement to be rejected, but it SUCCEEDED with {result!r}")


def _wait_for_table_active(ddb, table_name, timeout_s=90.0, interval_s=1.0):
    """Poll DescribeTable until ACTIVE. CreateTable is eventually consistent, so a
    transient ResourceNotFoundException counts as "not yet", never a failure."""
    deadline = time.monotonic() + timeout_s
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
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never went ACTIVE in {timeout_s}s (last={status})")


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
        Tags=_TAGS_KV,
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_for_table_active(ddb, table_name)
    return table_name


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement MUST reject syntactically invalid PartiQL with ValidationException."""
    ddb = ctx.client("dynamodb")
    table_name = _create_simple_table(ddb, ctx)

    # Positive control: well-formed PartiQL against the same table succeeds, so a rejection
    # below is attributable to the malformed syntax rather than ExecuteStatement being broken
    # or blocked outright.
    ddb.execute_statement(Statement=f'SELECT * FROM "{table_name}"')

    def bad_statement():
        return ddb.execute_statement(Statement=f'SELCT * FROM "{table_name}"')

    code, message = _error_code_and_message(bad_statement)
    assert code == "ValidationException", (
        f"expected ValidationException for malformed PartiQL, got {code!r}"
    )
    expected_message = "Statement wasn't well formed, can't be processed: Expected data manipulation"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Each further statement breaks the grammar a different way; AWS's parser names the break
    # in its message, so a different mistake must produce a different exact message.
    other_malformed_statements = [
        (f'SELECT * FROM "{table_name}" FOO', "Aliasing is not supported"),
        (
            f"SELECT * FROM \"{table_name}\" WHERE pk = 'abc",
            "Statement wasn't well formed, can't be processed: ",
        ),
        ("SELECT *", "Statement wasn't well formed, can't be processed: Expected FROM after SELECT list"),
        (
            f'SELECT * FROM "{table_name}";;',
            "Statement wasn't well formed, can't be processed: Unexpected token after semicolon. "
            "(Only one query is allowed.)",
        ),
        (
            f'SELECT * FROM "{table_name}" WHERE',
            "Statement wasn't well formed, can't be processed: Unexpected term",
        ),
    ]
    for statement, expected in other_malformed_statements:
        code, message = _error_code_and_message(lambda statement=statement: ddb.execute_statement(Statement=statement))
        assert code == "ValidationException", (
            f"expected ValidationException for {statement!r}, got {code!r}"
        )
        assert message == expected, f"for {statement!r}: expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
