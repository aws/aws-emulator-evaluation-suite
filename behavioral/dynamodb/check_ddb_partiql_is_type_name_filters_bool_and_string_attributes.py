"""ddb-partiql-is-type-name-filters-bool-and-string-attributes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ddb-partiql-is-type-name-filters-bool-and-string-attributes"
GROUP = "partiql"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PartiQL's `attr IS <type name>` predicate selects exactly the items whose stored attribute
    type matches the named type; a missing attribute and a value stored under a different type
    both fail it.
    """
    ddb = ctx.client("dynamodb")
    name = _make_table(ctx)
    _seed(ctx, name)

    bool_matches = _select_pks(ddb, name, "flag IS BOOL")
    assert bool_matches == _BOOL_TYPED, (
        f"flag IS BOOL returned {sorted(bool_matches)!r}, expected the BOOL-typed items "
        f"{sorted(_BOOL_TYPED)!r} only -- a missing attribute and a STRING-typed 'true' must not match"
    )

    string_matches = _select_pks(ddb, name, "s IS STRING")
    assert string_matches == _STRING_TYPED, (
        f"s IS STRING returned {sorted(string_matches)!r}, expected the STRING-typed items "
        f"{sorted(_STRING_TYPED)!r} only -- an N-typed value must not match"
    )


# Four items under a `pk` (S) HASH key. `flag` is BOOL for two items, STRING for one, and absent
# for one; `s` is STRING for three items and NUMBER for one. Every expected set below is derived
# from this seed, never typed separately.
_SEED_ITEMS = (
    {"pk": {"S": "bool-true"}, "flag": {"BOOL": True}, "s": {"S": "alpha"}},
    {"pk": {"S": "bool-false"}, "flag": {"BOOL": False}, "s": {"N": "7"}},
    {"pk": {"S": "no-flag"}, "s": {"S": "beta"}},
    {"pk": {"S": "flag-as-string"}, "flag": {"S": "true"}, "s": {"S": "gamma"}},
)

_BOOL_TYPED = frozenset(i["pk"]["S"] for i in _SEED_ITEMS if "flag" in i and "BOOL" in i["flag"])
_STRING_TYPED = frozenset(i["pk"]["S"] for i in _SEED_ITEMS if "S" in i["s"])


def _make_table(ctx) -> str:
    """An on-demand table keyed by pk (S) HASH only."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-ddbistype-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    return name


def _seed(ctx, name: str) -> None:
    ddb = ctx.client("dynamodb")
    for item in _SEED_ITEMS:
        ddb.put_item(TableName=name, Item=item)


def _select_pks(ddb, name: str, where: str) -> frozenset:
    pks, token = [], None
    while True:
        extra = {"NextToken": token} if token else {}
        page = ddb.execute_statement(
            Statement=f'SELECT pk FROM "{name}" WHERE {where}', ConsistentRead=True, **extra
        )
        pks.extend(i["pk"]["S"] for i in page["Items"])
        token = page.get("NextToken")
        if not token:
            return frozenset(pks)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
