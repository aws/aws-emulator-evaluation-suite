"""transact-write-items-client-token-idempotent-mismatch-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "transact-write-items-client-token-idempotent-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing a TransactWriteItems ClientRequestToken with different item content raises
    IdempotentParameterMismatchException with the exact message and leaves the first write's value v1.
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _wait_table_active(ddb, table_name)

    token = str(uuid.uuid4())

    ddb.transact_write_items(
        TransactItems=[
            {
                "Put": {
                    "TableName": table_name,
                    "Item": {"pk": {"S": "idem-item"}, "val": {"S": "v1"}},
                }
            }
        ],
        ClientRequestToken=token,
    )
    got = ddb.get_item(TableName=table_name, Key={"pk": {"S": "idem-item"}})
    val = got.get("Item", {}).get("val", {}).get("S")
    assert val == "v1", f"positive control: expected initial write to land as 'v1', got {val!r}"

    # Same token, different item content -> must be a mismatch, not applied.
    code, message = _error(
        lambda: ddb.transact_write_items(
            TransactItems=[
                {
                    "Put": {
                        "TableName": table_name,
                        "Item": {
                            "pk": {"S": "idem-item"},
                            "val": {"S": "v2-DIFFERENT"},
                        },
                    }
                }
            ],
            ClientRequestToken=token,
        )
    )
    assert code == "IdempotentParameterMismatchException", (
        f"expected IdempotentParameterMismatchException, got {code!r}"
    )
    expected = (
        "Specified idempotent token was used with different request parameters within the "
        "idempotency window"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    still = ddb.get_item(TableName=table_name, Key={"pk": {"S": "idem-item"}})
    still_val = still.get("Item", {}).get("val", {}).get("S")
    assert still_val == "v1", (
        f"rejected mismatch must leave the original item untouched, got val={still_val!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a mismatched replay real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected IdempotentParameterMismatchException, but the call SUCCEEDED and returned {result!r}"
    )


def _wait_table_active(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never became ACTIVE")


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
