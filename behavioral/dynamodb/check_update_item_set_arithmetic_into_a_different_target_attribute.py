"""update-item-set-arithmetic-into-a-different-target-attribute."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-set-arithmetic-into-a-different-target-attribute"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_TABLE_ACTIVE_BUDGET_S = 120.0
_TEARDOWN_WAIT_S = 120.0


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


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
    """SET writes an arithmetic result into an attribute other than the one it reads, for
    `path + value`, `path - value` and `value + path`, leaving the source untouched.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "item"}}
    ddb.put_item(TableName=table, Item={**key, "price": {"N": "20"}})

    # path + value, writing into a target attribute that does not exist yet.
    first = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET derived = price + :tax",
        ExpressionAttributeValues={":tax": {"N": "5"}}, ReturnValues="UPDATED_NEW",
    )["Attributes"]
    assert first == {"derived": {"N": "25"}}, (
        f"SET derived = price + :tax with price=20, :tax=5 returned UPDATED_NEW {first!r}, "
        f"expected only derived=25"
    )
    item1 = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert item1 == {**key, "price": {"N": "20"}, "derived": {"N": "25"}}, (
        f"after SET derived = price + :tax the item is {item1!r}, expected price unchanged at 20 "
        f"and derived=25"
    )

    # path - value, overwriting the target attribute; the source is still untouched.
    second = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET derived = price - :discount",
        ExpressionAttributeValues={":discount": {"N": "3"}}, ReturnValues="ALL_NEW",
    )["Attributes"]
    assert second == {**key, "price": {"N": "20"}, "derived": {"N": "17"}}, (
        f"SET derived = price - :discount with price=20, :discount=3 returned ALL_NEW {second!r}, "
        f"expected price=20 and derived=17"
    )
    item2 = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert item2 == second, f"after SET derived = price - :discount the item is {item2!r}, expected {second!r}"

    # value + path (value-first operand order), into the same different target attribute.
    third = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET derived = :tax + price",
        ExpressionAttributeValues={":tax": {"N": "5"}}, ReturnValues="ALL_NEW",
    )["Attributes"]
    assert third == {**key, "price": {"N": "20"}, "derived": {"N": "25"}}, (
        f"SET derived = :tax + price with :tax=5, price=20 returned ALL_NEW {third!r}, "
        f"expected price=20 and derived=25"
    )
    item3 = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert item3 == third, f"after SET derived = :tax + price the item is {item3!r}, expected {third!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
