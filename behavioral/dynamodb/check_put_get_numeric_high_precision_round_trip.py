"""put-get-numeric-high-precision-round-trip."""
from __future__ import annotations

from decimal import Decimal

from behavioral_harness import tags

CHECK = "put-get-numeric-high-precision-round-trip"
GROUP = "representation"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Number attribute with 38 significant digits and a negative exponent survives
    PutItem/GetItem exactly, without float rounding."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx)

    # 38 significant digits, value well below 1 (i.e. a large negative exponent in
    # normalized scientific form): 0.<20 zeros><38 digits>
    significant_digits = "12345678901234567890123456789012345678"
    assert len(significant_digits) == 38, (
        f"test literal must carry 38 significant digits, got {len(significant_digits)}"
    )
    num_str = "0." + ("0" * 20) + significant_digits

    pk = ctx.unique_name("item-")
    ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "num": {"N": num_str}})

    resp = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)
    item = resp.get("Item")
    assert item is not None, "item not found after PutItem"
    returned = item["num"]["N"]

    expected = Decimal(num_str)
    actual = Decimal(returned)
    assert actual == expected, f"numeric precision lost: {actual} != {expected}"


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
