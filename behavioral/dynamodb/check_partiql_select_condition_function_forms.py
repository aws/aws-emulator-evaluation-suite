"""partiql-select-condition-function-forms."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-select-condition-function-forms"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _table(ctx) -> str:
    """A pk/sk table for PartiQL SELECT statements."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-pqlcf-")
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
    """A PartiQL SELECT WHERE clause evaluates NOT, an upper-case function name, a boolean
    comparison, a double-quoted attribute name, a nested path and an OR of functions exactly.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-functions.html
    """
    ddb = ctx.client("dynamodb")
    t = _table(ctx)
    ddb.put_item(TableName=t, Item={
        "pk": {"S": "p1"}, "sk": {"S": "a1"},
        "m": {"M": {"sub": {"S": "x"}}}, "ss": {"SS": ["x", "y"]},
    })
    ddb.put_item(TableName=t, Item={
        "pk": {"S": "p1"}, "sk": {"S": "a2"},
        "m": {"M": {"sub": {"S": "y"}}},
    })
    ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": "b1"}})

    not_exists = _select(ddb, f'SELECT * FROM "{t}" WHERE pk=\'p1\' AND NOT attribute_exists(m)')
    assert not_exists == (("p1", "b1"),), (
        f"NOT attribute_exists(m) returned {not_exists!r}, expected the one item lacking m"
    )

    not_begins_with = _select(ddb, f'SELECT * FROM "{t}" WHERE pk=\'p1\' AND NOT begins_with("sk", \'a\')')
    assert not_begins_with == (("p1", "b1"),), (
        f"NOT begins_with(sk, 'a') returned {not_begins_with!r}, expected the one sk not starting 'a'"
    )

    upper_exists = _select(ddb, f'SELECT * FROM "{t}" WHERE pk=\'p1\' AND ATTRIBUTE_EXISTS(m)')
    assert upper_exists == (("p1", "a1"), ("p1", "a2")), (
        f"upper-case ATTRIBUTE_EXISTS(m) returned {upper_exists!r}, expected the two items carrying m"
    )

    bool_cmp = _select(ddb, f'SELECT * FROM "{t}" WHERE pk=\'p1\' AND attribute_exists(m) = true')
    assert bool_cmp == (("p1", "a1"), ("p1", "a2")), (
        f"attribute_exists(m) = true returned {bool_cmp!r}, expected the two items carrying m"
    )

    quoted_name = _select(ddb, f'SELECT * FROM "{t}" WHERE pk=\'p1\' AND attribute_exists("ss")')
    assert quoted_name == (("p1", "a1"),), (
        f'attribute_exists("ss") returned {quoted_name!r}, expected only the item carrying ss'
    )

    nested_present = _select(ddb, f'SELECT * FROM "{t}" WHERE pk=\'p1\' AND attribute_exists(m.sub)')
    assert nested_present == (("p1", "a1"), ("p1", "a2")), (
        f"attribute_exists(m.sub) returned {nested_present!r}, expected the two items carrying m.sub"
    )

    nested_absent = _select(ddb, f'SELECT * FROM "{t}" WHERE pk=\'p1\' AND attribute_not_exists(m.nope)')
    assert nested_absent == (("p1", "a1"), ("p1", "a2"), ("p1", "b1")), (
        f"attribute_not_exists(m.nope) returned {nested_absent!r}, expected every item (m.nope never exists)"
    )

    or_of_functions = _select(
        ddb, f'SELECT * FROM "{t}" WHERE pk=\'p1\' AND (attribute_exists("ss") OR attribute_exists(m))'
    )
    assert or_of_functions == (("p1", "a1"), ("p1", "a2")), (
        f"(attribute_exists(ss) OR attribute_exists(m)) returned {or_of_functions!r}, "
        "expected the two items carrying ss or m"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
