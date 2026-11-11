"""put-get-binary-blob-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-get-binary-blob-round-trip"
GROUP = "representation"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A base64-transported Binary (B) attribute round-trips through PutItem/GetItem with
    identical byte content, including all 256 byte values."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx)

    pk = ctx.unique_name("item-")
    payload = bytes(range(256))

    ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "blob": {"B": payload}})

    resp = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)
    item = resp.get("Item")
    assert item is not None, "item not found after PutItem"
    returned = item["blob"]["B"]
    # botocore decodes Binary shapes back to raw bytes for the JSON protocol.
    assert bytes(returned) == payload, "binary payload changed across round-trip"


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
