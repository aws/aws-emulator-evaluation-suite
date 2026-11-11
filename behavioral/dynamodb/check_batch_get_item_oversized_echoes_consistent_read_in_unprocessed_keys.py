"""batch-get-item-oversized-echoes-consistent-read-in-unprocessed-keys."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-item-oversized-echoes-consistent-read-in-unprocessed-keys"
GROUP = "batch"
SERVICES = ["dynamodb"]

# 44 items of 380 KiB total about 17.1 MB, just over the 16 MB BatchGetItem response limit.
_N_ITEMS = 44
_PAYLOAD_BYTES = 380 * 1024


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A BatchGetItem too large to answer in one response defers keys into UnprocessedKeys that
    carries the same ConsistentRead value the request asked for, true or false.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-bgicr-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    payload = "z" * _PAYLOAD_BYTES
    all_keys = [f"k{i:02d}" for i in range(_N_ITEMS)]
    for key in all_keys:
        ddb.put_item(TableName=table, Item={"pk": {"S": key}, "pad": {"S": payload}})
    keys = [{"pk": {"S": k}} for k in all_keys]

    for consistent_read in (True, False):
        resp = ddb.batch_get_item(RequestItems={
            table: {"Keys": keys, "ConsistentRead": consistent_read},
        })
        spec = resp.get("UnprocessedKeys", {}).get(table)
        assert spec is not None, (
            f"{_N_ITEMS!r} items of {_PAYLOAD_BYTES!r} bytes must not fit one response, so "
            f"ConsistentRead={consistent_read!r} should leave {table} in UnprocessedKeys, got "
            f"{resp.get('UnprocessedKeys')!r}"
        )
        assert spec.get("ConsistentRead") == consistent_read, (
            f"UnprocessedKeys for ConsistentRead={consistent_read!r} echoed "
            f"{spec.get('ConsistentRead')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
