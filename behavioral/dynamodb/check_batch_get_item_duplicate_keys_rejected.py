"""batch-get-item-duplicate-keys-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-get-item-duplicate-keys-rejected"
GROUP = "ordering"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetItem rejects a request that specifies the same primary key more than once
    within a single table's Keys list with ValidationException, rather than silently
    deduplicating it."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    ddb.put_item(TableName=table, Item={"pk": {"S": "dup-1"}, "val": {"S": "v1"}})

    code, message = _error(
        lambda: ddb.batch_get_item(
            RequestItems={
                table: {
                    "Keys": [
                        {"pk": {"S": "dup-1"}},
                        {"pk": {"S": "dup-1"}},
                    ]
                }
            }
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Provided list of item keys contains duplicates", (
        f"expected the duplicate-keys refusal message, got {message!r}"
    )

    # Control: the same call with the duplicate removed succeeds normally.
    resp = ddb.batch_get_item(RequestItems={table: {"Keys": [{"pk": {"S": "dup-1"}}]}})
    items = resp["Responses"][table]
    assert len(items) == 1, f"expected exactly 1 item for the deduplicated key, got {items!r}"
    assert items[0]["pk"]["S"] == "dup-1", f"expected pk 'dup-1' back, got {items[0]!r}"


def _create_table(ctx, ddb) -> str:
    name = ctx.unique_name("sim2real-behav-bgidup-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    _wait_table_active(ddb, name)
    return name


def _wait_table_active(ddb, name: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"table {name} never became ACTIVE")


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a request real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
