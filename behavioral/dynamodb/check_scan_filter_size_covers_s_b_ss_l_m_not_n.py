"""scan-filter-size-covers-s-b-ss-l-m-not-n."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-size-covers-s-b-ss-l-m-not-n"
GROUP = "scan"
SERVICES = ["dynamodb"]

#: pk -> item. "match" and "other" share every attribute name but differ in size for each
#: type, so a filter that selects by the wrong metric (bytes vs characters, a nested value
#: instead of a count) would pick the wrong row or both.
_ITEMS = {
    "match": {
        "s": {"S": "abc"}, "b": {"B": b"XY"}, "ss": {"SS": ["p", "q", "r"]},
        "l": {"L": [{"N": "1"}, {"N": "2"}]},
        "m": {"M": {"x": {"N": "1"}, "y": {"N": "2"}}},
        "n": {"N": "7"},
    },
    "other": {
        "s": {"S": "abcdef"}, "b": {"B": b"XYZAB"}, "ss": {"SS": ["p", "q", "r", "s"]},
        "l": {"L": [{"N": "1"}, {"N": "2"}, {"N": "3"}]},
        "m": {"M": {"x": {"N": "1"}, "y": {"N": "2"}, "z": {"N": "3"}}},
        "n": {"N": "42"},
    },
}

#: (attribute, size of "match"'s value) -- the size every type's filter below selects on.
_SIZES = (("s", 3), ("b", 2), ("ss", 3), ("l", 2), ("m", 2))


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression's size() selects by a String's characters, a Binary's bytes, a
    Set's or List's element count and a Map's key count -- in parenthesized form too -- and on a
    Number it always evaluates false rather than the number's own value.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbscnsz-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for pk, attrs in _ITEMS.items():
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, **attrs})

    def scan_pks(expr: str, values: dict) -> set:
        resp = ddb.scan(
            TableName=table, ConsistentRead=True,
            FilterExpression=expr, ExpressionAttributeValues=values,
        )
        return {i["pk"]["S"] for i in resp["Items"]}

    for attr, n in _SIZES:
        got = scan_pks(f"size({attr}) = :n", {":n": {"N": str(n)}})
        assert got == {"match"}, f"size({attr}) = {n} selected {sorted(got)!r}, expected ['match']"

    # The parenthesized form around the whole function call parses and evaluates identically.
    for attr, n in _SIZES:
        got = scan_pks(f"(size({attr})) = :n", {":n": {"N": str(n)}})
        assert got == {"match"}, f"(size({attr})) = {n} selected {sorted(got)!r}, expected ['match']"

    # size() on a Number is unsupported: the comparison evaluates false for every item, even
    # against the number's own stored value -- never an error, and never a numeric answer.
    empty_gt = scan_pks("size(n) > :zero", {":zero": {"N": "0"}})
    assert empty_gt == set(), f"size(n) > 0 selected {sorted(empty_gt)!r}, expected none"

    empty_eq = scan_pks("size(n) = :seven", {":seven": {"N": "7"}})
    assert empty_eq == set(), (
        f"size(n) = 7 selected {sorted(empty_eq)!r} even though 'match'.n is 7; size() must not "
        "fall back to the number's own value"
    )

    # Positive control: comparing n directly (no size()) still selects exactly the matching item,
    # proving the table and the comparator work and that size() alone is what excludes N.
    control = scan_pks("n = :seven", {":seven": {"N": "7"}})
    assert control == {"match"}, f"n = 7 selected {sorted(control)!r}, expected ['match']"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
