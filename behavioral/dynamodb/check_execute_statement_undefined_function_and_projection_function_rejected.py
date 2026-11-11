"""execute-statement-undefined-function-and-projection-function-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-undefined-function-and-projection-function-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"call unexpectedly SUCCEEDED where ValidationException was required: {resp!r}")


def _wait_for_table_active(ddb, ctx, table_name):
    """Poll DescribeTable until ACTIVE, bounded by the runner's own remaining budget."""
    deadline = time.monotonic() + max(1.0, min(90.0, (ctx.time_left() or 90.0) - 10.0))
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
    raise AssertionError(f"table {table_name!r} never went ACTIVE within budget (last={status!r})")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement refuses a function it does not define, and refuses any function placed
    in the SELECT projection list, both with ValidationException naming the exact token position,
    and each leaves the table untouched.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-functions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_for_table_active(ddb, ctx, table)

    key = {"pk": {"S": "item"}, "sk": {"S": "row"}}
    ddb.put_item(TableName=table, Item={**key, "note": {"S": "original"}})

    # A function DynamoDB does not define, used inside an UPDATE's WHERE clause.
    undefined_fn = "made_up_function"
    update_stmt = (
        f'UPDATE "{table}" SET note = \'changed\' WHERE pk = \'item\' AND sk = \'row\' AND '
        f'{undefined_fn}(note) = true'
    )
    col = update_stmt.index(undefined_fn) + 1
    expected_undefined_message = f"Unrecognized function: {undefined_fn} at 1:{col}:{len(undefined_fn)}"

    code, message = _error(lambda: ddb.execute_statement(Statement=update_stmt))
    assert code == "ValidationException", (
        f"UPDATE calling undefined function {undefined_fn!r} answered {code!r} ({message!r}), "
        f"expected ValidationException"
    )
    assert message == expected_undefined_message, (
        f"undefined-function message was {message!r}, expected {expected_undefined_message!r}"
    )
    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged["note"]["S"] == "original", (
        f"UPDATE calling an undefined function must write nothing, but note is now "
        f"{unchanged['note']!r}"
    )

    # A function DynamoDB DOES define, used in the SELECT projection list rather than a
    # condition: the projection list itself cannot carry a function call.
    defined_fn = "attribute_exists"
    select_stmt = f'SELECT {defined_fn}(note) FROM "{table}"'
    col = select_stmt.index(defined_fn) + 1
    expected_projection_message = f"Unexpected path component at 1:{col}:{len(defined_fn)}"

    code, message = _error(lambda: ddb.execute_statement(Statement=select_stmt))
    assert code == "ValidationException", (
        f"SELECT projecting {defined_fn}(note) answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    assert message == expected_projection_message, (
        f"function-in-projection message was {message!r}, expected {expected_projection_message!r}"
    )
    unread = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unread["note"]["S"] == "original", (
        f"a rejected SELECT must write nothing, but note is now {unread['note']!r}"
    )

    # Positive control: the same function, used in a WHERE clause rather than the projection
    # list, is accepted.
    rows = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE {defined_fn}(note)'
    )["Items"]
    assert len(rows) == 1 and rows[0]["note"]["S"] == "original", (
        f"attribute_exists(note) in a WHERE clause must select the item, got {rows!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
