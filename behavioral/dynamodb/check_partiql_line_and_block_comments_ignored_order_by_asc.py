"""partiql-line-and-block-comments-ignored-order-by-asc."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-line-and-block-comments-ignored-order-by-asc"
GROUP = 'partiql'
SERVICES = ['dynamodb']


def _wait_for_table_active(ddb, table_name, timeout_s=90.0, interval_s=1.0):
    """Poll DescribeTable until ACTIVE; CreateTable is eventually consistent."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            status = "PENDING"
        if status == "ACTIVE":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never went ACTIVE in {timeout_s}s (last={status})")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement ignores '--' line comments and '/* */' block comments anywhere in the
    statement, and ORDER BY sk ASC returns ascending sort-key order.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqlcmt-")
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "N"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_for_table_active(ddb, table)

    for sk in (1, 2, 3):
        ddb.put_item(TableName=table, Item={"pk": {"S": "A"}, "sk": {"N": str(sk)}})

    keyed_item = {"pk": {"S": "A"}, "sk": {"N": "2"}}

    forms = {
        "leading --": (
            f"-- a leading comment\nSELECT * FROM \"{table}\" WHERE pk='A' AND sk=2"
        ),
        "trailing --": (
            f"SELECT * FROM \"{table}\" WHERE pk='A' AND sk=2 -- a trailing comment"
        ),
        "-- between FROM and WHERE": (
            f"SELECT * FROM \"{table}\" -- between FROM and WHERE\nWHERE pk='A' AND sk=2"
        ),
        "/* */ block comment": (
            f"SELECT * FROM \"{table}\" /* a block comment */ WHERE pk='A' AND sk=2"
        ),
    }
    for name, statement in forms.items():
        result = ddb.execute_statement(Statement=statement, ConsistentRead=True)
        items = result["Items"]
        assert items == [keyed_item], (
            f"{name}: expected exactly the one keyed item {keyed_item!r}, got {items!r}"
        )

    ascending = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\" WHERE pk='A' ORDER BY sk ASC", ConsistentRead=True
    )["Items"]
    ascending_keys = [i["sk"]["N"] for i in ascending]
    assert ascending_keys == ["1", "2", "3"], (
        f"ORDER BY sk ASC must return sort keys in ascending order (1, 2, 3), got {ascending_keys!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
