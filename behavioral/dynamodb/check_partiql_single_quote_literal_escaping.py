"""partiql-single-quote-literal-escaping."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-single-quote-literal-escaping"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def expect_error(fn, code: str, message: str) -> None:
    """Call fn(); assert the ClientError it raises carries exactly (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        actual = (err.get("Code"), err.get("Message"))
        assert actual == (code, message), f"expected {(code, message)!r}, got {actual!r}"
        return
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


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement writes a doubled single quote inside a string literal as one literal
    apostrophe, and refuses a backslash before a quote with ValidationException, writing nothing.
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-pqesc-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_for_table_active(ddb, table_name)

    # Case A: a doubled single quote inside a string literal is one literal apostrophe.
    ddb.execute_statement(
        Statement=f"INSERT INTO \"{table_name}\" VALUE {{'pk': 'doubled', 'val': 'rock''n''roll'}}"
    )
    written = ddb.get_item(TableName=table_name, Key={"pk": {"S": "doubled"}}, ConsistentRead=True)
    assert written.get("Item", {}).get("val") == {"S": "rock'n'roll"}, (
        f"expected val to round-trip as {{'S': \"rock'n'roll\"}}, got {written.get('Item')!r}"
    )

    selected = ddb.execute_statement(
        Statement=f"SELECT val FROM \"{table_name}\" WHERE pk = 'doubled'"
    )
    assert selected["Items"] == [{"val": {"S": "rock'n'roll"}}], (
        f"expected SELECT to return the doubled-quote value, got {selected['Items']!r}"
    )

    # Case B: a backslash before a quote does not escape it; the statement is refused and
    # nothing is written. Positive control: Case A already proves a well-formed INSERT succeeds.
    _BACKSLASH_REFUSED = ("ValidationException", "Statement wasn't well formed, can't be processed: ")
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f"INSERT INTO \"{table_name}\" VALUE {{'pk': 'backslash', 'val': 'rock\\'n\\'roll'}}"
        ),
        *_BACKSLASH_REFUSED,
    )
    unwritten = ddb.get_item(TableName=table_name, Key={"pk": {"S": "backslash"}}, ConsistentRead=True)
    assert "Item" not in unwritten, f"expected no write after refusal, got {unwritten.get('Item')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
