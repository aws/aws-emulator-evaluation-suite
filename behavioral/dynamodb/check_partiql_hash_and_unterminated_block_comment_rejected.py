"""partiql-hash-and-unterminated-block-comment-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-hash-and-unterminated-block-comment-rejected"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_NOT_WELL_FORMED = ("ValidationException", "Statement wasn't well formed, can't be processed: ")


def _error_code_and_message(fn):
    """The Error.Code and Error.Message ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected ExecuteStatement to be rejected, but it SUCCEEDED with {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error_code_and_message(fn)
    assert got_code == code, f"expected error code {code!r}, got {got_code!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _wait_for_table_active(ddb, table_name, timeout_s=90.0, interval_s=1.0):
    """Poll DescribeTable until ACTIVE; CreateTable is eventually consistent."""
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


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement refuses a '#' line comment and an unterminated '/*' block comment with
    the bare not-well-formed envelope, never treating either as an ignorable comment marker.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqlcmtrej-")
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "N"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_for_table_active(ddb, table)

    ddb.put_item(TableName=table, Item={"pk": {"S": "A"}, "sk": {"N": "2"}})
    keyed_item = {"pk": {"S": "A"}, "sk": {"N": "2"}}

    # Positive control: the same clause with no comment marker succeeds, so the refusals below
    # are attributable to the comment form rather than the clause itself.
    control = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\" WHERE pk='A' AND sk=2", ConsistentRead=True
    )["Items"]
    assert control == [keyed_item], f"positive control must return the keyed item, got {control!r}"

    expect_error(
        lambda: ddb.execute_statement(
            Statement=f"SELECT * FROM \"{table}\" WHERE pk='A' AND sk=2 # a hash comment"
        ),
        *_NOT_WELL_FORMED,
    )
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f"SELECT * FROM \"{table}\" WHERE pk='A' AND sk=2 /* unterminated"
        ),
        *_NOT_WELL_FORMED,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
