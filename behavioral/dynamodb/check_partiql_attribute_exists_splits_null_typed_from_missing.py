"""partiql-attribute-exists-splits-null-typed-from-missing."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-attribute-exists-splits-null-typed-from-missing"
GROUP = "partiql"
SERVICES = ["dynamodb"]

#: pk, sk, whether the item carries attribute "a" and with what value (None = omit the attribute).
_SEED = (
    ("p1", 1, {"S": "hello"}),
    ("p1", 2, None),
    ("p1", 3, {"NULL": True}),
    ("p2", 1, {"S": "world"}),
    ("p2", 2, None),
    ("p3", 1, {"NULL": True}),
)

_WITH_KEY_PINNED = tuple(sorted((pk, sk) for pk, sk, a in _SEED if pk == "p1" and a is not None))
_WITHOUT_KEY_PINNED = tuple(sorted((pk, sk) for pk, sk, a in _SEED if pk == "p1" and a is None))
_WITH_FULL = tuple(sorted((pk, sk) for pk, sk, a in _SEED if a is not None))
_WITHOUT_FULL = tuple(sorted((pk, sk) for pk, sk, a in _SEED if a is None))


def _make_table(ctx) -> str:
    """An on-demand table keyed by pk (S) HASH + sk (N) RANGE."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-ddbae-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "N"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    return name


def _seed(ctx, name: str) -> None:
    """Write every seed item with one PutItem each, so a NULL-typed `a` is stored, not omitted."""
    ddb = ctx.client("dynamodb")
    for pk, sk, a in _SEED:
        item = {"pk": {"S": pk}, "sk": {"N": str(sk)}}
        if a is not None:
            item["a"] = a
        ddb.put_item(TableName=name, Item=item)


def _select(ddb, statement: str) -> tuple:
    """Every page of a consistent ExecuteStatement, as a sorted set of (pk, sk)."""
    items, token = [], None
    while True:
        extra = {"NextToken": token} if token else {}
        page = ddb.execute_statement(Statement=statement, ConsistentRead=True, **extra)
        items.extend(page["Items"])
        token = page.get("NextToken")
        if not token:
            return tuple(sorted((i["pk"]["S"], int(i["sk"]["N"])) for i in items))


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PartiQL attribute_exists/attribute_not_exists treat a NULL-typed attribute as present,

    on both a partition-pinned SELECT and a full-table SELECT.
    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-functions.exists.html
    """
    ddb = ctx.client("dynamodb")
    name = _make_table(ctx)
    _seed(ctx, name)

    pinned_exists = _select(ddb, f'SELECT * FROM "{name}" WHERE pk = \'p1\' AND attribute_exists(a)')
    assert pinned_exists == _WITH_KEY_PINNED, (
        f"key-pinned attribute_exists(a) returned {pinned_exists!r}, expected {_WITH_KEY_PINNED!r}"
    )

    pinned_not_exists = _select(
        ddb, f'SELECT * FROM "{name}" WHERE pk = \'p1\' AND attribute_not_exists(a)'
    )
    assert pinned_not_exists == _WITHOUT_KEY_PINNED, (
        f"key-pinned attribute_not_exists(a) returned {pinned_not_exists!r}, expected "
        f"{_WITHOUT_KEY_PINNED!r}"
    )

    full_exists = _select(ddb, f'SELECT * FROM "{name}" WHERE attribute_exists(a)')
    assert full_exists == _WITH_FULL, (
        f"full-table attribute_exists(a) returned {full_exists!r}, expected {_WITH_FULL!r}"
    )

    full_not_exists = _select(ddb, f'SELECT * FROM "{name}" WHERE attribute_not_exists(a)')
    assert full_not_exists == _WITHOUT_FULL, (
        f"full-table attribute_not_exists(a) returned {full_not_exists!r}, expected {_WITHOUT_FULL!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
