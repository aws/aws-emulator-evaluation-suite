"""update-item-set-value-first-operand-order-same-attribute."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-set-value-first-operand-order-same-attribute"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_TABLE_ACTIVE_BUDGET_S = 120.0
_TEARDOWN_WAIT_S = 120.0


def _delete_table_when_possible(ddb, table_name):
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


def _create_table(ctx, ddb):
    name = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_when_possible(ddb, name))
    deadline = time.monotonic() + _TABLE_ACTIVE_BUDGET_S
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return name
        time.sleep(2.0)
    raise AssertionError(f"table {name!r} not ACTIVE within {_TABLE_ACTIVE_BUDGET_S}s: {status!r}")


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """SET n = :value + n (value-first operand order) adds against the currently stored n,
    leaving a sibling attribute untouched, and compounds over successive updates.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "item"}}
    ddb.put_item(TableName=table, Item={**key, "n": {"N": "10"}, "label": {"S": "keep"}})

    first = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET n = :inc + n",
        ExpressionAttributeValues={":inc": {"N": "5"}}, ReturnValues="UPDATED_NEW",
    )["Attributes"]
    assert first == {"n": {"N": "15"}}, (
        f"SET n = :inc + n with n=10, :inc=5 returned UPDATED_NEW {first!r}, expected only n=15"
    )
    item1 = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert item1 == {**key, "n": {"N": "15"}, "label": {"S": "keep"}}, (
        f"after SET n = :inc + n the item is {item1!r}, expected n=15 and label untouched"
    )

    # A second value-first update against the now-stored n=15, never the original n=10.
    second = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET n = :inc + n",
        ExpressionAttributeValues={":inc": {"N": "7"}}, ReturnValues="ALL_NEW",
    )["Attributes"]
    assert second == {**key, "n": {"N": "22"}, "label": {"S": "keep"}}, (
        f"SET n = :inc + n with the stored n=15, :inc=7 returned ALL_NEW {second!r}, "
        f"expected n=22 (not 17, which would mean it ignored the first update)"
    )
    item2 = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert item2 == second, f"after the second SET n = :inc + n the item is {item2!r}, expected {second!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
