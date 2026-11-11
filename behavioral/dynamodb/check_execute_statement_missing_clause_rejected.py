"""execute-statement-missing-clause-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-missing-clause-rejected"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_SELECT_NO_FROM_MESSAGE = "Statement wasn't well formed, can't be processed: Expected FROM after SELECT list"
_UPDATE_NO_SET_REMOVE_MESSAGE = "Statement wasn't well formed, can't be processed: Expected data manipulation"
_INSERT_NO_VALUE_MESSAGE = "Statement wasn't well formed, can't be processed: Unexpected term"
_DELETE_NO_WHERE_MESSAGE = "Where clause does not contain a mandatory equality on all key attributes"
_NON_DML_LEADING_MESSAGE = "Unsupported operation: DropTable"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected ExecuteStatement to be rejected, but it succeeded: {result!r}")


def _wait_active(ddb, table_name, timeout_s=90.0, interval_s=1.0):
    """Poll DescribeTable until ACTIVE."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never went ACTIVE in {timeout_s}s (last={status})")


def _item(ddb, table_name, pk):
    resp = ddb.execute_statement(Statement=f"SELECT * FROM \"{table_name}\" WHERE pk='{pk}'")
    return resp["Items"]


def _assert_rejected(ddb, statement, expected_message):
    code, message = _error(lambda: ddb.execute_statement(Statement=statement))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == expected_message, f"unexpected message {message!r}"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement rejects SELECT without FROM, UPDATE without SET/REMOVE, INSERT
    without VALUE, DELETE without WHERE and a non-DML leading keyword, and writes nothing.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.html
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-tbl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_active(ddb, table_name)

    # Positive control / seed: a well-formed INSERT succeeds.
    ddb.execute_statement(Statement=f"INSERT INTO \"{table_name}\" VALUE {{'pk': 'seed', 'n': 1}}")
    seed = _item(ddb, table_name, "seed")
    assert seed and seed[0]["n"] == {"N": "1"}, f"seed item missing or wrong after a well-formed INSERT: {seed!r}"

    # SELECT without FROM.
    _assert_rejected(ddb, "SELECT *", _SELECT_NO_FROM_MESSAGE)

    # UPDATE without SET or REMOVE.
    _assert_rejected(ddb, f"UPDATE \"{table_name}\" WHERE pk='seed'", _UPDATE_NO_SET_REMOVE_MESSAGE)
    seed = _item(ddb, table_name, "seed")
    assert seed[0]["n"] == {"N": "1"}, f"a rejected UPDATE without SET/REMOVE changed n to {seed[0].get('n')!r}"

    # INSERT without VALUE.
    _assert_rejected(ddb, f"INSERT INTO \"{table_name}\"", _INSERT_NO_VALUE_MESSAGE)

    # DELETE without WHERE.
    _assert_rejected(ddb, f"DELETE FROM \"{table_name}\"", _DELETE_NO_WHERE_MESSAGE)
    assert _item(ddb, table_name, "seed"), "a rejected DELETE without WHERE removed the seed item"

    # A non-DML leading keyword.
    _assert_rejected(ddb, f"DROP TABLE \"{table_name}\"", _NON_DML_LEADING_MESSAGE)
    status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
    assert status == "ACTIVE", f"table status {status!r} after a rejected DROP TABLE"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
