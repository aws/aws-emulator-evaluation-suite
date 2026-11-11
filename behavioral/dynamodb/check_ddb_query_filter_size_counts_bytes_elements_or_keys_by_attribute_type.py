"""ddb-query-filter-size-counts-bytes-elements-or-keys-by-attribute-type."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ddb-query-filter-size-counts-bytes-elements-or-keys-by-attribute-type"
GROUP = "query"
SERVICES = ["dynamodb"]

#: sk -> item attrs. Each attribute's two variants are built so that counting its serialized
#: bytes or its nested characters, rather than B-bytes / L-and-SS-elements / M-keys, would give
#: the opposite ordering -- a coincidental match cannot pass these assertions.
_ITEMS = {
    "b-small": {"bval": {"B": b"ABC"}},
    "b-big": {"bval": {"B": b"ABCDEFG"}},
    "l-small": {"lval": {"L": [{"S": "x" * 50}, {"S": "y" * 50}]}},
    "l-big": {"lval": {"L": [{"N": "1"}, {"N": "2"}, {"N": "3"}, {"N": "4"}, {"N": "5"}]}},
    "ss-small": {"ssval": {"SS": ["a" * 20, "b" * 20]}},
    "ss-big": {"ssval": {"SS": ["a", "b", "c", "d", "e"]}},
    "m-small": {"mval": {"M": {"a": {"S": "x" * 50}, "b": {"S": "y" * 50}}}},
    "m-big": {"mval": {"M": {"a": {"N": "1"}, "b": {"N": "2"}, "c": {"N": "3"}, "d": {"N": "4"}, "e": {"N": "5"}}}},
}

#: (attribute name, size of the "-small" item, size of the "-big" item).
_CASES = (
    ("bval", 3, 7),
    ("lval", 2, 5),
    ("ssval", 2, 5),
    ("mval", 2, 5),
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query FilterExpression's size() counts B's bytes, L's and SS's elements, and M's keys --
    not a nested character or serialized-byte total -- selecting exactly the item of that size.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbfsz-")
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

    def by_size(attr: str, n: int) -> set:
        resp = ddb.query(
            TableName=table, KeyConditionExpression="pk = :p", ConsistentRead=True,
            FilterExpression=f"size({attr}) = :n",
            ExpressionAttributeValues={":p": {"S": "probe"}, ":n": {"N": str(n)}},
        )
        return {i["sk"]["S"] for i in resp["Items"]}

    for attr, small_n, big_n in _CASES:
        kind = attr[:-3]
        small_sk, big_sk = f"{kind}-small", f"{kind}-big"
        got_small = by_size(attr, small_n)
        assert got_small == {small_sk}, (
            f"size({attr}) = {small_n} selected {sorted(got_small)!r}, expected [{small_sk!r}]"
        )
        got_big = by_size(attr, big_n)
        assert got_big == {big_sk}, (
            f"size({attr}) = {big_n} selected {sorted(got_big)!r}, expected [{big_sk!r}]"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
