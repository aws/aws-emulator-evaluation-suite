"""partiql-contains-and-begins-with-select-exact-matching-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-contains-and-begins-with-select-exact-matching-set"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_MATCH = "match"
_NOMATCH = "nomatch"
_MISSING = "missing"

#: pk -> attribute values. "missing" carries none of the tested attributes at all.
_ITEMS = {
    _MATCH: {
        "s_attr": {"S": "hello world"},
        "ss_attr": {"SS": ["red", "green", "blue"]},
        "ns_attr": {"NS": ["1", "2", "3"]},
        "l_attr": {"L": [{"S": "apple"}, {"S": "banana"}]},
        "sbw_attr": {"S": "foobar"},
        "bbw_attr": {"B": b"ABCDEF"},
    },
    _NOMATCH: {
        "s_attr": {"S": "goodbye"},
        "ss_attr": {"SS": ["yellow", "purple"]},
        "ns_attr": {"NS": ["10", "20"]},
        "l_attr": {"L": [{"S": "cherry"}, {"S": "date"}]},
        "sbw_attr": {"S": "barfoo"},
        "bbw_attr": {"B": b"XYZ123"},
    },
    _MISSING: {},
}


def _make_table(ctx) -> str:
    """An on-demand table keyed by pk (S) HASH only."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-ddbcb-")
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
    for pk, attrs in _ITEMS.items():
        ddb.put_item(TableName=name, Item={"pk": {"S": pk}, **attrs})


def _select_pks(ddb, name: str, where: str, parameters=None) -> frozenset:
    items, token = [], None
    kwargs = {"Parameters": parameters} if parameters is not None else {}
    while True:
        extra = {"NextToken": token} if token else {}
        page = ddb.execute_statement(
            Statement=f'SELECT pk FROM "{name}" WHERE {where}', ConsistentRead=True, **kwargs,
            **extra,
        )
        items.extend(page["Items"])
        token = page.get("NextToken")
        if not token:
            return frozenset(i["pk"]["S"] for i in items)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PartiQL contains() on S/SS/NS/L and begins_with() on S/B select exactly the matching item,

    never the item holding a non-matching value or the item missing the attribute entirely.
    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-functions.contains.html
    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-functions.beginswith.html
    """
    ddb = ctx.client("dynamodb")
    name = _make_table(ctx)
    _seed(ctx, name)
    want = frozenset({_MATCH})

    s_got = _select_pks(ddb, name, "contains(s_attr, 'wor')")
    assert s_got == want, f"contains(s_attr, 'wor') returned {sorted(s_got)!r}, expected {sorted(want)!r}"

    ss_got = _select_pks(ddb, name, "contains(ss_attr, 'red')")
    assert ss_got == want, f"contains(ss_attr, 'red') returned {sorted(ss_got)!r}, expected {sorted(want)!r}"

    ns_got = _select_pks(ddb, name, "contains(ns_attr, 2)")
    assert ns_got == want, f"contains(ns_attr, 2) returned {sorted(ns_got)!r}, expected {sorted(want)!r}"

    l_got = _select_pks(ddb, name, "contains(l_attr, 'banana')")
    assert l_got == want, f"contains(l_attr, 'banana') returned {sorted(l_got)!r}, expected {sorted(want)!r}"

    sbw_got = _select_pks(ddb, name, "begins_with(sbw_attr, 'foo')")
    assert sbw_got == want, (
        f"begins_with(sbw_attr, 'foo') returned {sorted(sbw_got)!r}, expected {sorted(want)!r}"
    )

    bbw_got = _select_pks(ddb, name, "begins_with(bbw_attr, ?)", parameters=[{"B": b"ABC"}])
    assert bbw_got == want, (
        f"begins_with(bbw_attr, ?) with B prefix returned {sorted(bbw_got)!r}, expected {sorted(want)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
