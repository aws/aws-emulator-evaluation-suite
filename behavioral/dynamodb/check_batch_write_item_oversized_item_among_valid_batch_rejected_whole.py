"""batch-write-item-oversized-item-among-valid-batch-rejected-whole."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-item-oversized-item-among-valid-batch-rejected-whole"
GROUP = "limits"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"
LIMIT_BYTES = 409600


def _item_of_size(pk_value: str, filler_attr: str, total_bytes: int) -> dict:
    """A one-pk, one-filler-attribute item whose attribute-value length totals total_bytes."""
    overhead = len("pk".encode()) + len(pk_value.encode()) + len(filler_attr.encode())
    filler_len = total_bytes - overhead
    assert filler_len > 0, f"{total_bytes} bytes is too small for this item shape"
    return {"pk": {"S": pk_value}, filler_attr: {"S": "x" * filler_len}}


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_table_active(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never became ACTIVE")


def _safe_delete_table(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchWriteItem refuses the whole call with ValidationException when one of 25
    PutRequests exceeds the item size limit, writing none of the 24 valid siblings
    either, while the same 24 valid items alone are accepted in full."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table))
    _wait_table_active(ddb, table)

    valid_pks = [f"bw-mix-ok-{i:03d}" for i in range(24)]
    valid_requests = [
        {"PutRequest": {"Item": {"pk": {"S": pk}, "data": {"S": "fine"}}}} for pk in valid_pks
    ]
    oversized_pk = "bw-mix-oversized"
    oversized_item = _item_of_size(oversized_pk, "data", LIMIT_BYTES + 1)
    mixed_requests = valid_requests + [{"PutRequest": {"Item": oversized_item}}]

    code, message = _error(lambda: ddb.batch_write_item(RequestItems={table: mixed_requests}))
    assert code == ERR_VALIDATION, (
        f"a batch with one over-{LIMIT_BYTES}-byte PutRequest among 24 valid ones must be "
        f"{ERR_VALIDATION} for the whole call, got {code!r}: {message!r}"
    )
    assert message == "Item size has exceeded the maximum allowed size", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    for pk in valid_pks[:3] + [oversized_pk]:
        after = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)
        assert "Item" not in after, (
            f"the request is rejected as a whole, so {pk!r} must not be written, "
            f"got {after.get('Item')!r}"
        )

    control_resp = ddb.batch_write_item(RequestItems={table: valid_requests})
    unprocessed = control_resp.get("UnprocessedItems", {}).get(table, [])
    assert not unprocessed, (
        f"expected the same 24 valid puts alone to be fully accepted, "
        f"got {len(unprocessed)} unprocessed: {unprocessed!r}"
    )
    control_got = ddb.get_item(
        TableName=table, Key={"pk": {"S": valid_pks[0]}}, ConsistentRead=True
    ).get("Item")
    assert control_got is not None, (
        f"expected control item {valid_pks[0]!r} to be written once the oversized sibling is removed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
