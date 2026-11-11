"""batch-write-item-full-batch-accepted."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-write-item-full-batch-accepted"
GROUP = "overly-permissive"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchWriteItem accepts a full batch of 25 puts to a table with a local secondary index in one call,
    with no UnprocessedItems, and a Query then counts all 25 items."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "lsi_sk", "AttributeType": "S"},
        ],
        LocalSecondaryIndexes=[
            {
                "IndexName": "lsi1",
                "KeySchema": [
                    {"AttributeName": "pk", "KeyType": "HASH"},
                    {"AttributeName": "lsi_sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _wait_table_active(ddb, table_name)

    # Bounded, cheap control: a batch of items well under the 10 GB
    # collection limit, all sharing one partition key, must be accepted in
    # full - this is the real, asserted oracle for this check.
    shared_pk = "collection-under-limit"
    put_requests = [
        {
            "PutRequest": {
                "Item": {
                    "pk": {"S": shared_pk},
                    "sk": {"S": f"sk-{i:03d}"},
                    "lsi_sk": {"S": f"lsi-{i:03d}"},
                    "payload": {"S": "x" * 1024},
                }
            }
        }
        for i in range(25)
    ]
    resp = ddb.batch_write_item(RequestItems={table_name: put_requests})
    assert not resp.get("UnprocessedItems"), (
        f"expected all under-limit writes to be accepted, got unprocessed items: "
        f"{resp.get('UnprocessedItems')!r}"
    )

    query = ddb.query(
        TableName=table_name,
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": {"S": shared_pk}},
    )
    assert query["Count"] == 25, (
        f"expected 25 items written under the shared partition key, found {query['Count']}"
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
