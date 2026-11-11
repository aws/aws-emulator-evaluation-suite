"""execute-statement-function-requires-document-path-or-operand-count-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-function-requires-document-path-or-operand-count-rejected"
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
    """ExecuteStatement/UPDATE refuses attribute_exists given a literal or a `?` parameter in
    place of a document path, and given 0 or 3 operands, each with ValidationException, and
    leaves the item untouched; the same function over a real path still gates the write.

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

    base_update = f'UPDATE "{table}" SET note = \'changed\' WHERE pk = \'item\' AND sk = \'row\' AND '

    doc_path_message = (
        "Operator or function requires a document path; operator or function: attribute_exists"
    )
    operand_count_message = (
        "Incorrect number of operands for operator or function; operator or function: "
        "attribute_exists, number of operands: {n}"
    )

    cases = [
        ("literal in place of a document path", base_update + "attribute_exists('note')", None, doc_path_message),
        ("? parameter in place of a document path", base_update + "attribute_exists(?)",
         [{"S": "note"}], doc_path_message),
        ("0 operands", base_update + "attribute_exists()", None, operand_count_message.format(n=0)),
        ("3 operands", base_update + "attribute_exists(note, note, note)", None,
         operand_count_message.format(n=3)),
    ]

    for label, statement, params, expected_message in cases:
        kwargs = {"Statement": statement}
        if params is not None:
            kwargs["Parameters"] = params
        code, message = _error(lambda kwargs=kwargs: ddb.execute_statement(**kwargs))
        assert code == "ValidationException", (
            f"UPDATE with attribute_exists ({label}) answered {code!r} ({message!r}), expected "
            f"ValidationException"
        )
        assert message == expected_message, (
            f"UPDATE with attribute_exists ({label}) message was {message!r}, expected "
            f"{expected_message!r}"
        )

        unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
        assert unchanged["note"]["S"] == "original", (
            f"UPDATE with attribute_exists ({label}) must write nothing, but note is now "
            f"{unchanged['note']!r}"
        )

    # Positive control: the same function over a real document path gates the write correctly.
    ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET note = \'changed\' WHERE pk = \'item\' AND sk = \'row\' '
                  'AND attribute_exists(note)'
    )
    gated = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert gated["note"]["S"] == "changed", (
        f"attribute_exists(note) over a real path must gate the write, got {gated['note']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
