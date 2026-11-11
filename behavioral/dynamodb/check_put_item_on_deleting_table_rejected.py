"""put-item-on-deleting-table-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-item-on-deleting-table-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]


def _error(fn):
    """Return (code, message) of the ClientError ``fn`` raises; an accepted call fails the check."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After DeleteTable, PutItem on the table is refused within 120 s with ResourceNotFoundException ("Requested
    resource not found") and DescribeTable raises the same code with the exact message; AWS may accept writes
    while the table is DELETING.
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-delfa-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Positive control: PutItem succeeds while the table is ACTIVE.
    ddb.put_item(TableName=table_name, Item={"pk": {"S": "seed"}, "val": {"S": "before-delete"}})

    ddb.delete_table(TableName=table_name)

    from botocore.exceptions import ClientError

    code = message = None
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            # A table in DELETING may still accept the write; keep polling until it refuses.
            ddb.put_item(TableName=table_name, Item={"pk": {"S": "post-delete"}, "val": {"S": "x"}})
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message")
            if code == "ResourceNotFoundException":
                break
        time.sleep(3.0)
    else:
        raise AssertionError(f"PutItem was not refused within 120s after DeleteTable; last code {code!r}")

    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, saw {code!r}"
    assert message == "Requested resource not found", f"unexpected PutItem message {message!r}"

    # Effect absent: the table itself is gone too, confirming the rejection matches real state.
    describe_code, describe_message = _error(lambda: ddb.describe_table(TableName=table_name))
    assert describe_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, saw {describe_code!r}"
    )
    expected = f"Requested resource not found: Table: {table_name} not found"
    assert describe_message == expected, f"unexpected DescribeTable message {describe_message!r}"


def _safe_delete_table(ddb, table_name):
    from botocore.exceptions import ClientError

    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
