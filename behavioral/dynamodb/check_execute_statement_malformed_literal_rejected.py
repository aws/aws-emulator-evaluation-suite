"""execute-statement-malformed-literal-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-malformed-literal-rejected"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_EMPTY_TAIL_MESSAGE = "Statement wasn't well formed, can't be processed: "
_UNCLOSED_ITEM_MESSAGE = "Statement wasn't well formed, can't be processed: Expected RIGHT_CURLY"
_UNCLOSED_SET_MESSAGE = "Statement wasn't well formed, can't be processed: Expected RIGHT_DOUBLE_ANGLE_BRACKET"


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
    """ExecuteStatement rejects an INSERT whose literal is malformed at the lexical level —
    an unterminated string, a number split from its exponent, an unclosed {...} item
    literal, an unclosed <<...>> set literal — with ValidationException, and writes nothing.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.insert.html
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

    # Positive control: a well-formed INSERT succeeds.
    ddb.execute_statement(Statement=f"INSERT INTO \"{table_name}\" VALUE {{'pk': 'seed'}}")
    assert _item(ddb, table_name, "seed"), "seed item missing after a well-formed INSERT"

    # Unterminated string literal.
    _assert_rejected(
        ddb, f"INSERT INTO \"{table_name}\" VALUE {{'pk': 'px, 'sk': 'sx'}}", _EMPTY_TAIL_MESSAGE
    )
    assert _item(ddb, table_name, "px") == [], "an unterminated-string INSERT still wrote an item"

    # Number split from its exponent (a trailing 'e' with no exponent digits).
    _assert_rejected(
        ddb, f"INSERT INTO \"{table_name}\" VALUE {{'pk': 'py', 'n': 1e}}", _EMPTY_TAIL_MESSAGE
    )
    assert _item(ddb, table_name, "py") == [], "a split-exponent INSERT still wrote an item"

    # Malformed {...} item literal: no closing brace.
    _assert_rejected(
        ddb, f"INSERT INTO \"{table_name}\" VALUE {{'pk': 'pz'", _UNCLOSED_ITEM_MESSAGE
    )
    assert _item(ddb, table_name, "pz") == [], "an unclosed-item-literal INSERT still wrote an item"

    # Malformed <<...>> set literal: no closing double angle bracket.
    _assert_rejected(
        ddb,
        f"INSERT INTO \"{table_name}\" VALUE {{'pk': 'pw', 'tags': <<'a', 'b'}}",
        _UNCLOSED_SET_MESSAGE,
    )
    assert _item(ddb, table_name, "pw") == [], "an unclosed-set-literal INSERT still wrote an item"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
