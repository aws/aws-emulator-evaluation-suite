"""ddb-query-filter-size-counts-binary-set-number-set-elements-and-nested-map-keys."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ddb-query-filter-size-counts-binary-set-number-set-elements-and-nested-map-keys"
GROUP = "query"
SERVICES = ["dynamodb"]

#: sk -> item attrs. Each pair's "-small"/"-big" variant is built so that counting a
#: different metric (total bytes, total digits, or the outer map's own key count instead of
#: the nested map's) gives the opposite ordering, so a coincidental match cannot pass.
_ITEMS = {
    "bs-small": {"bsval": {"BS": [b"x" * 10, b"y" * 10]}},
    "bs-big": {"bsval": {"BS": [b"a" * 2, b"b" * 2, b"c" * 2, b"d" * 2]}},
    "ns-small": {"nsval": {"NS": ["99999999", "88888888"]}},
    "ns-big": {"nsval": {"NS": ["1", "2", "3", "4"]}},
    "map-small": {
        "mval": {"M": {
            "child": {"M": {"a": {"N": "1"}, "b": {"N": "2"}}},
            "k1": {"S": "x"}, "k2": {"S": "y"},
        }},
    },
    "map-big": {
        "mval": {"M": {
            "child": {"M": {"a": {"N": "1"}, "b": {"N": "2"}, "c": {"N": "3"}, "d": {"N": "4"}}},
        }},
    },
}

#: (sk prefix, expression path, name map, size of "-small" item, size of "-big" item).
_CASES = (
    ("bs", "bsval", None, 2, 4),
    ("ns", "nsval", None, 2, 4),
    ("map", "#o.#c", {"#o": "mval", "#c": "child"}, 2, 4),
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query FilterExpression's size() counts a Binary Set's and a Number Set's elements and a
    nested map's own keys -- not a byte total, a digit total or the enclosing map's key count.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbfszx-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                               {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for sk, attrs in _ITEMS.items():
        ddb.put_item(TableName=table, Item={"pk": {"S": "probe"}, "sk": {"S": sk}, **attrs})

    def by_size(path: str, names: dict | None, n: int) -> set:
        kwargs = {
            "TableName": table, "KeyConditionExpression": "pk = :p", "ConsistentRead": True,
            "FilterExpression": f"size({path}) = :n",
            "ExpressionAttributeValues": {":p": {"S": "probe"}, ":n": {"N": str(n)}},
        }
        if names:
            kwargs["ExpressionAttributeNames"] = names
        resp = ddb.query(**kwargs)
        return {i["sk"]["S"] for i in resp["Items"]}

    for prefix, path, names, small_n, big_n in _CASES:
        small_sk, big_sk = f"{prefix}-small", f"{prefix}-big"
        got_small = by_size(path, names, small_n)
        assert got_small == {small_sk}, (
            f"size({path}) = {small_n} selected {sorted(got_small)!r}, expected [{small_sk!r}]"
        )
        got_big = by_size(path, names, big_n)
        assert got_big == {big_sk}, (
            f"size({path}) = {big_n} selected {sorted(got_big)!r}, expected [{big_sk!r}]"
        )

    # Positive control: size() on the outer map alone (3 keys vs. 1) proves the table and the
    # comparator work and that size(mval.child) above is reading the nested map, not mval itself.
    outer_control = by_size("mval", None, 3)
    assert outer_control == {"map-small"}, (
        f"size(mval) = 3 selected {sorted(outer_control)!r}, expected [{'map-small'!r}]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
