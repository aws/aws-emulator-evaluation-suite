"""put-get-unicode-string-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-get-unicode-string-round-trip"
GROUP = "representation"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Multi-script unicode string attributes round-trip byte-identical via PutItem/GetItem."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx)

    pk = ctx.unique_name("item-")
    values = {
        "emoji": "\U0001F600\U0001F389\U0001F680 rocket party",
        "cjk": "\u65e5\u672c\u8a9e\u6f22\u5b57\u30c6\u30b9\u30c8",
        "rtl": "\u0645\u0631\u062d\u0628\u0627 \u0628\u0627\u0644\u0639\u0627\u0644\u0645",
        "mixed": "H\u00e9llo W\u00f6rld \u00dcn\u00efcode \u26a1 test",
    }

    item = {"pk": {"S": pk}}
    for k, v in values.items():
        item[k] = {"S": v}

    ddb.put_item(TableName=table, Item=item)

    resp = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)
    got = resp.get("Item")
    assert got is not None, "item not found after PutItem"
    for k, v in values.items():
        assert got[k]["S"] == v, f"attribute {k} mismatch: {got[k]['S']!r} != {v!r}"


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
