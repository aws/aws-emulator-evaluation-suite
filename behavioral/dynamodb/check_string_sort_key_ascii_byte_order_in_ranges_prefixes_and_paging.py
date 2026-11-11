"""string-sort-key-ascii-byte-order-in-ranges-prefixes-and-paging."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "string-sort-key-ascii-byte-order-in-ranges-prefixes-and-paging"
GROUP = "query"
SERVICES = ["dynamodb"]

# UTF-8 byte order, which disagrees with case-insensitive or locale collation.
_BYTE_ORDER = ["A", "B", "Z", "_", "a", "a b", "a-b", "aZ", "a_z", "ab", "b", "é", "中"]
_BETWEEN_UNDERSCORE_AND_B = ["_", "a", "a b", "a-b", "aZ", "a_z", "ab", "b"]
_BEGINS_WITH_A = ["a", "a b", "a-b", "aZ", "a_z", "ab"]


def _teardown(undo, *not_found, timeout_s=300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo():
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table and its indexes are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _sks(resp):
    return [it["sk"]["S"] for it in resp["Items"]]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """String sort keys order by UTF-8 bytes (A < Z < _ < a, a-b < aZ < a_z < ab) both directions;
    BETWEEN and begins_with select by bytes, and a Limit=1 walk visits each key once in that order.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-strord-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    for sk in reversed(_BYTE_ORDER):
        ddb.put_item(TableName=table, Item={"pk": {"S": "p"}, "sk": {"S": sk}})

    base = {"TableName": table, "ConsistentRead": True}
    part = {**base, "KeyConditionExpression": "pk = :p", "ExpressionAttributeValues": {":p": {"S": "p"}}}

    got = _sks(ddb.query(**part))
    assert got == _BYTE_ORDER, f"forward Query order {got!r}, expected UTF-8 byte order {_BYTE_ORDER!r}"
    got = _sks(ddb.query(**part, ScanIndexForward=False))
    assert got == list(reversed(_BYTE_ORDER)), f"reverse Query order {got!r} is not the mirror"

    got = _sks(ddb.query(
        **base, KeyConditionExpression="pk = :p AND sk BETWEEN :lo AND :hi",
        ExpressionAttributeValues={":p": {"S": "p"}, ":lo": {"S": "_"}, ":hi": {"S": "b"}},
    ))
    assert got == _BETWEEN_UNDERSCORE_AND_B, f"sk BETWEEN '_' AND 'b' selected {got!r}"

    got = _sks(ddb.query(
        **base, KeyConditionExpression="pk = :p AND begins_with(sk, :pre)",
        ExpressionAttributeValues={":p": {"S": "p"}, ":pre": {"S": "a"}},
    ))
    assert got == _BEGINS_WITH_A, f"begins_with(sk, 'a') selected {got!r}"

    for forward, want in ((True, _BYTE_ORDER), (False, list(reversed(_BYTE_ORDER)))):
        walk, kwargs = [], {**part, "Limit": 1, "ScanIndexForward": forward}
        while True:
            resp = ddb.query(**kwargs)
            walk.extend(_sks(resp))
            if "LastEvaluatedKey" not in resp:
                break
            assert len(walk) <= len(want), f"Limit=1 walk forward={forward} overran: {walk!r}"
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
        assert walk == want, f"Limit=1 walk forward={forward} visited {walk!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
