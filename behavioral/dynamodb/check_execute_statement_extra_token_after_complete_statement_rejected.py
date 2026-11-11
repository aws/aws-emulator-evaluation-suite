"""execute-statement-extra-token-after-complete-statement-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-extra-token-after-complete-statement-rejected"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_EXTRA_TOKEN_MESSAGE = "Statement wasn't well formed, can't be processed: Unexpected token after expression"


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


def _assert_rejected(ddb, statement):
    code, message = _error(lambda: ddb.execute_statement(Statement=statement))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == _EXTRA_TOKEN_MESSAGE, f"unexpected message {message!r}"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement rejects SELECT, INSERT, UPDATE and DELETE each carrying one extra
    token after an otherwise-complete statement, with ValidationException, and writes nothing.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ExecuteStatement.html
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

    # Positive control: a well-formed INSERT with no trailing token succeeds.
    ddb.execute_statement(Statement=f"INSERT INTO \"{table_name}\" VALUE {{'pk': 'seed', 'n': 1}}")
    seed = _item(ddb, table_name, "seed")
    assert seed and seed[0]["n"] == {"N": "1"}, f"seed item missing or wrong after a well-formed INSERT: {seed!r}"

    # SELECT: a trailing token is rejected.
    _assert_rejected(ddb, f"SELECT * FROM \"{table_name}\" WHERE pk='seed' EXTRA")

    # INSERT: the attempted new item never appears.
    _assert_rejected(ddb, f"INSERT INTO \"{table_name}\" VALUE {{'pk': 'new'}} EXTRA")
    assert _item(ddb, table_name, "new") == [], "a rejected INSERT with a trailing token still wrote an item"

    # UPDATE: the seed item's attribute stays at its pre-update value.
    _assert_rejected(ddb, f"UPDATE \"{table_name}\" SET n = 2 WHERE pk='seed' EXTRA")
    seed = _item(ddb, table_name, "seed")
    assert seed[0]["n"] == {"N": "1"}, f"a rejected UPDATE with a trailing token changed n to {seed[0].get('n')!r}"

    # DELETE: the seed item survives.
    _assert_rejected(ddb, f"DELETE FROM \"{table_name}\" WHERE pk='seed' EXTRA")
    assert _item(ddb, table_name, "seed"), "a rejected DELETE with a trailing token removed the item"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
