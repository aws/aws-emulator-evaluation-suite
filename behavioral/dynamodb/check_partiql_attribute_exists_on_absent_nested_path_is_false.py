"""partiql-attribute-exists-on-absent-nested-path-is-false."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-attribute-exists-on-absent-nested-path-is-false"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _table(ctx) -> str:
    """A pk/sk table for PartiQL SELECT statements."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-pqane-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    return name


def _select(ddb, statement: str) -> tuple:
    """Every matching (pk, sk), as a sorted set, from a consistent SELECT."""
    items, token = [], None
    while True:
        extra = {"NextToken": token} if token else {}
        page = ddb.execute_statement(Statement=statement, ConsistentRead=True, **extra)
        items.extend(page["Items"])
        token = page.get("NextToken")
        if not token:
            return tuple(sorted((i["pk"]["S"], i["sk"]["S"]) for i in items))


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL WHERE clause's attribute_exists on a nested path evaluates false whenever that
    path is absent, whether its parent map is present with other keys or missing entirely.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-functions.html
    """
    ddb = ctx.client("dynamodb")
    t = _table(ctx)
    ddb.put_item(TableName=t, Item={
        "pk": {"S": "p1"}, "sk": {"S": "a1"},
        "m": {"M": {"sub": {"S": "x"}}},
    })
    ddb.put_item(TableName=t, Item={
        "pk": {"S": "p1"}, "sk": {"S": "a2"},
        "m": {"M": {}},
    })
    ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": "a3"}})

    nested_present = _select(ddb, f'SELECT * FROM "{t}" WHERE pk=\'p1\' AND attribute_exists(m.sub)')
    assert nested_present == (("p1", "a1"),), (
        f"attribute_exists(m.sub) returned {nested_present!r}, expected only the item carrying m.sub"
    )

    nested_absent = _select(ddb, f'SELECT * FROM "{t}" WHERE pk=\'p1\' AND attribute_exists(m.nope)')
    assert nested_absent == (), (
        f"attribute_exists(m.nope) returned {nested_absent!r}, expected none: m.nope is absent on "
        "every item, whether m itself is present (empty or non-empty) or missing entirely"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
