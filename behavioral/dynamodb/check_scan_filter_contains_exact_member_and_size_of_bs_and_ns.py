"""scan-filter-contains-exact-member-and-size-of-bs-and-ns."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filter-contains-exact-member-and-size-of-bs-and-ns"
GROUP = "scan"
SERVICES = ["dynamodb"]

#: pk -> {bs: BinarySet, ns: NumberSet}. "other" carries every member of "match" plus one
#: extra of each type, so a count-based or membership-based filter that picked the wrong
#: metric would pick the wrong row or both.
_ITEMS = {
    "match": {"bs": {"BS": [b"\x01", b"\x02", b"\x03"]}, "ns": {"NS": ["1", "2", "42"]}},
    "other": {
        "bs": {"BS": [b"\x01", b"\x02", b"\x03", b"\x04"]},
        "ns": {"NS": ["1", "2", "42", "100"]},
    },
}


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression's contains() matches a Binary Set only by an exact member, never
    a byte-extension of one, and size() of a Binary Set or Number Set equals its member count.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbbsns-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for pk, attrs in _ITEMS.items():
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, **attrs})

    def scan_pks(expr: str, values: dict) -> set:
        resp = ddb.scan(
            TableName=table, ConsistentRead=True,
            FilterExpression=expr, ExpressionAttributeValues=values,
        )
        return {i["pk"]["S"] for i in resp["Items"]}

    # contains() on a Binary Set matches exactly the item whose set holds that exact member.
    only_other = scan_pks("contains(bs, :v)", {":v": {"B": b"\x04"}})
    assert only_other == {"other"}, (
        f"contains(bs, (B)0x04) selected {sorted(only_other)!r}, expected only ['other']"
    )

    # A byte-extension of a member is not itself a member: contains() tests set membership by
    # exact equality, never a byte-prefix or substring match the way scalar Binary contains() does.
    extension = scan_pks("contains(bs, :v)", {":v": {"B": b"\x04\x00"}})
    assert extension == set(), (
        f"contains(bs, (B)0x0400) selected {sorted(extension)!r}, expected none: 0x0400 is not a "
        "member of either set even though it extends a member byte-for-byte"
    )

    # Positive control: a member shared by both items' sets matches both, proving the mechanism
    # discriminates by exact membership rather than by excluding "other" outright.
    both = scan_pks("contains(bs, :v)", {":v": {"B": b"\x01"}})
    assert both == {"match", "other"}, (
        f"contains(bs, (B)0x01) selected {sorted(both)!r}, expected both items: 0x01 is a member "
        "of each set"
    )

    # size() of a Binary Set or Number Set equals its member count, not a byte or digit count.
    for attr in ("bs", "ns"):
        got3 = scan_pks(f"size({attr}) = :n", {":n": {"N": "3"}})
        assert got3 == {"match"}, f"size({attr}) = 3 selected {sorted(got3)!r}, expected ['match']"
        got4 = scan_pks(f"size({attr}) = :n", {":n": {"N": "4"}})
        assert got4 == {"other"}, f"size({attr}) = 4 selected {sorted(got4)!r}, expected ['other']"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
