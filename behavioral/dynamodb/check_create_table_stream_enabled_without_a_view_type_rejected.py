"""create-table-stream-enabled-without-a-view-type-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-stream-enabled-without-a-view-type-rejected"
GROUP = "validation"
SERVICES = ["dynamodb"]

_KEY = {
    "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
}


def _wait_cap(ctx, cap_s: float) -> float:
    """cap_s, shortened when the runner stops the check sooner, keeping 5 s for the failure."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _drop_table(ddb, name: str):
    """A cleanup deleting the table, backing off while a create or tag update holds it; a failure raises."""

    def status() -> str:
        try:
            return ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return "GONE"

    def undo() -> None:
        for attempt in range(8):
            # A table just created can still read not-found, so GONE still sends the delete.
            if status() == "DELETING":
                return
            try:
                ddb.delete_table(TableName=name)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException" or attempt == 7:
                    raise
            time.sleep(min(3 * 2 ** attempt, 60))

    return undo


def _new_table(ctx, ddb, name: str, **params) -> dict:
    """CreateTable, its delete registered at once, then DescribeTable polled to ACTIVE."""
    ddb.create_table(TableName=name, **params)
    ctx.on_cleanup(_drop_table(ddb, name))
    deadline = time.monotonic() + _wait_cap(ctx, 240.0)
    while True:
        try:
            table = ddb.describe_table(TableName=name)["Table"]
        except ClientError as exc:
            # DescribeTable can read not-found for a moment after CreateTable.
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or time.monotonic() >= deadline:
                raise
            table = {"TableStatus": "CREATING"}
        if table["TableStatus"] == "ACTIVE" or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert table["TableStatus"] == "ACTIVE", f"table {name} settled at {table['TableStatus']!r}"
    return table


def _refusal(fn, code: str):
    """Call fn, which AWS must refuse with code; return the ClientError.

    A success fails the check, and a different code fails it raised from AWS's own error.
    """
    try:
        result = fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == code:
            return exc
        raise AssertionError(f"expected {code}, got {exc.response['Error']['Code']}") from exc
    raise AssertionError(f"expected {code}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable enabling a stream with no StreamViewType is refused and creates no table; the same
    create naming KEYS_ONLY succeeds and reads the stream back.
    """
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-dtsv-")
    ctx.on_cleanup(_drop_table(ddb, name))
    base = {"BillingMode": "PAY_PER_REQUEST", "Tags": [{"Key": "sim2real", "Value": CHECK}], **_KEY}

    err = _refusal(
        lambda: ddb.create_table(TableName=name, StreamSpecification={"StreamEnabled": True}, **base),
        "ValidationException",
    )
    no_view = (
        "One or more parameter values were invalid: Table is being created with a stream enabled, "
        "UpdateViewType is required"
    )
    message = err.response["Error"]["Message"]
    assert message == no_view, f"the refusal carried the message {message!r}"

    err = _refusal(lambda: ddb.describe_table(TableName=name), "ResourceNotFoundException")
    missing = f"Requested resource not found: Table: {name} not found"
    message = err.response["Error"]["Message"]
    assert message == missing, f"the refused name reads {message!r}, expected {missing!r}"

    stream = {"StreamEnabled": True, "StreamViewType": "KEYS_ONLY"}
    table = _new_table(ctx, ddb, name, StreamSpecification=stream, **base)
    assert table.get("StreamSpecification") == stream, (
        f"the accepted create reads StreamSpecification={table.get('StreamSpecification')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
