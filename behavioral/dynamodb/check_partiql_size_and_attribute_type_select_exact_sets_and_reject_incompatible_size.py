"""partiql-size-and-attribute-type-select-exact-sets-and-reject-incompatible-size."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "partiql-size-and-attribute-type-select-exact-sets-and-reject-incompatible-size"
GROUP = "partiql"
SERVICES = ["dynamodb"]

#: pk -> the AttributeValue stored under "val", one per attribute_type code under test.
_TYPE_ITEMS = {
    "type-s": {"S": "hello"},
    "type-n": {"N": "42"},
    "type-l": {"L": [{"S": "a"}, {"S": "b"}, {"S": "c"}]},
    "type-m": {"M": {"x": {"S": "1"}, "y": {"S": "2"}}},
    "type-ss": {"SS": ["a", "b", "c", "d"]},
    "type-null": {"NULL": True},
    "type-bool": {"BOOL": True},
}

#: (attribute name, threshold, pk of the item below the threshold, pk of the item above it).
_SIZE_CASES = (
    ("sval", 3, "size-s-small", "size-s-big"),
    ("bval", 3, "size-b-small", "size-b-big"),
    ("lval", 2, "size-l-small", "size-l-big"),
    ("mval", 2, "size-m-small", "size-m-big"),
    ("ssval", 2, "size-ss-small", "size-ss-big"),
)

#: pk -> {attribute name: AttributeValue}, one PutItem per size case's small/big pair.
_SIZE_ITEMS = {
    "size-s-small": {"sval": {"S": "ab"}},
    "size-s-big": {"sval": {"S": "abcdef"}},
    "size-b-small": {"bval": {"B": b"AB"}},
    "size-b-big": {"bval": {"B": b"ABCDEFGH"}},
    "size-l-small": {"lval": {"L": [{"N": "1"}]}},
    "size-l-big": {"lval": {"L": [{"N": "1"}, {"N": "2"}, {"N": "3"}]}},
    "size-m-small": {"mval": {"M": {"a": {"N": "1"}}}},
    "size-m-big": {"mval": {"M": {"a": {"N": "1"}, "b": {"N": "2"}, "c": {"N": "3"}}}},
    "size-ss-small": {"ssval": {"SS": ["a"]}},
    "size-ss-big": {"ssval": {"SS": ["a", "b", "c"]}},
}


def _make_table(ctx) -> str:
    """An on-demand table keyed by pk (S) HASH only."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-ddbsz-")
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
    for pk, val in _TYPE_ITEMS.items():
        ddb.put_item(TableName=name, Item={"pk": {"S": pk}, "val": val})
    for pk, attrs in _SIZE_ITEMS.items():
        ddb.put_item(TableName=name, Item={"pk": {"S": pk}, **attrs})


def _select_pks(ddb, name: str, where: str) -> frozenset:
    items, token = [], None
    while True:
        extra = {"NextToken": token} if token else {}
        page = ddb.execute_statement(
            Statement=f'SELECT pk FROM "{name}" WHERE {where}', ConsistentRead=True, **extra
        )
        items.extend(page["Items"])
        token = page.get("NextToken")
        if not token:
            return frozenset(i["pk"]["S"] for i in items)


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PartiQL attribute_type(val, code) selects exactly the item carrying that type; size(attr)

    selects exactly the items whose S/B/L/M/set attribute clears the threshold; an attribute_type
    code outside the documented set is refused with DynamoDB's exact validation error.
    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-functions.attribute_type.html
    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-functions.size.html
    """
    ddb = ctx.client("dynamodb")
    name = _make_table(ctx)
    _seed(ctx, name)

    # attribute_type: exactly the item whose stored type matches the requested code.
    for pk, value in _TYPE_ITEMS.items():
        code = next(iter(value))
        got = _select_pks(ddb, name, f"attribute_type(val, '{code}')")
        assert got == frozenset({pk}), (
            f"attribute_type(val, '{code}') returned {sorted(got)!r}, expected [{pk!r}]"
        )

    # size(): exactly the "-big" item clears the threshold; the "-small" one and every item that
    # lacks the attribute entirely do not.
    for attr, threshold, small_pk, big_pk in _SIZE_CASES:
        got = _select_pks(ddb, name, f"size({attr}) > {threshold}")
        assert got == frozenset({big_pk}), (
            f"size({attr}) > {threshold} returned {sorted(got)!r}, expected [{big_pk!r}]"
        )
        got_small = _select_pks(ddb, name, f"size({attr}) <= {threshold}")
        assert small_pk in got_small and big_pk not in got_small, (
            f"size({attr}) <= {threshold} returned {sorted(got_small)!r}; expected to contain "
            f"{small_pk!r} and exclude {big_pk!r}"
        )

    # Positive control: attribute_type rejects a code outside the documented set.
    try:
        result = ddb.execute_statement(
            Statement=f'SELECT pk FROM "{name}" WHERE attribute_type(val, \'NOTATYPE\')',
            ConsistentRead=True,
        )
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "ValidationException", f"attribute_type(val, 'NOTATYPE') raised {err['Code']!r}"
        expected_msg = (
            "Invalid attribute type name found; type: NOTATYPE, "
            "valid types: {N,BS,L,B,NULL,M,S,SS,NS,BOOL}"
        )
        assert err["Message"] == expected_msg, f"unexpected message: {err['Message']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
