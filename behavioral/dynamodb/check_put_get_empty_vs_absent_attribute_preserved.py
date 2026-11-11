"""put-get-empty-vs-absent-attribute-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-get-empty-vs-absent-attribute-preserved"
GROUP = "representation"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An empty String/Binary attribute is stored and returned distinctly from an
    attribute that was never written (absent), not coerced or dropped."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx)

    pk = ctx.unique_name("item-")
    ddb.put_item(
        TableName=table,
        Item={
            "pk": {"S": pk},
            "emptyStr": {"S": ""},
            "emptyBin": {"B": b""},
            "present": {"S": "x"},
            # "absentAttr" intentionally never written
        },
    )

    resp = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)
    item = resp.get("Item")
    assert item is not None, "item not found after PutItem"

    assert "emptyStr" in item, "empty string attribute was dropped"
    assert item["emptyStr"]["S"] == "", "empty string attribute was coerced"

    assert "emptyBin" in item, "empty binary attribute was dropped"
    assert bytes(item["emptyBin"]["B"]) == b"", "empty binary attribute was coerced"

    assert "present" in item and item["present"]["S"] == "x", (
        f"present attribute mismatch: {item.get('present')!r}"
    )
    assert "absentAttr" not in item, "absent attribute materialized on read-back"


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
