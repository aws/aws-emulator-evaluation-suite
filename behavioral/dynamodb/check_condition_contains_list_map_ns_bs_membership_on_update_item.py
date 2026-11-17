"""condition-contains-list-map-ns-bs-membership-on-update-item."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-contains-list-map-ns-bs-membership-on-update-item"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_COND_FAILED = ("ConditionalCheckFailedException", "The conditional request failed")

_NAMES = {
    "#tags": "tags", "#members": "members", "#nums": "nums", "#blobs": "blobs",
    "#codes": "codes", "#u": "u",
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


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success fails too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """contains() in an UpdateItem ConditionExpression tests List element, NS, BS and SS member
    equality, never substring or partial-map matching, across List, List-of-Map, NS, BS and SS.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-contains-mix-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    key = {"pk": {"S": "item"}}
    tags_attr = {"L": [{"S": "administrator"}, {"S": "viewer"}]}
    members_attr = {"L": [
        {"M": {"name": {"S": "admin"}, "role": {"S": "owner"}}},
        {"M": {"name": {"S": "viewer"}}},
    ]}
    nums_attr = {"NS": ["10", "20", "30"]}
    blobs_attr = {"BS": [b"\x01", b"\x02"]}
    codes_attr = {"SS": ["alpha-admin", "beta"]}
    base_item = {
        **key, "tags": tags_attr, "members": members_attr, "nums": nums_attr,
        "blobs": blobs_attr, "codes": codes_attr,
    }
    ddb.put_item(TableName=table, Item=base_item)

    def read():
        item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
        for set_attr in ("nums", "blobs", "codes"):
            item[set_attr] = {next(iter(item[set_attr])): frozenset(next(iter(item[set_attr].values())))}
        return item

    def update(path: str, value: dict, mark: str):
        ddb.update_item(
            TableName=table, Key=key, UpdateExpression="SET #u = :mark",
            ConditionExpression=f"contains({path}, :v)",
            ExpressionAttributeNames={"#u": "u", path: _NAMES[path]},
            ExpressionAttributeValues={":v": value, ":mark": {"S": mark}},
        )

    baseline = read()

    # --- List: a substring of an element is not an element; exact element match is ---
    expect_error(lambda: update("#tags", {"S": "admin"}, "list-substring"), *_COND_FAILED)
    got = read()
    assert got == baseline, f"UpdateItem under a failing list-substring contains() left {got!r}"

    update("#tags", {"S": "administrator"}, "list-exact")
    got = read()
    assert got["u"] == {"S": "list-exact"}, (
        f"UpdateItem under a holding list-element contains() left u={got.get('u')!r}"
    )
    marked = {**baseline, "u": {"S": "list-exact"}}

    # --- List-of-Map: a map missing one key of an element is not that element; the whole,
    # exactly matching map is ---
    expect_error(lambda: update("#members", {"M": {"name": {"S": "admin"}}}, "map-partial"), *_COND_FAILED)
    got = read()
    assert got == marked, f"UpdateItem under a failing partial-map contains() left {got!r}"

    update("#members", {"M": {"name": {"S": "admin"}, "role": {"S": "owner"}}}, "map-exact")
    got = read()
    assert got["u"] == {"S": "map-exact"}, (
        f"UpdateItem under a holding whole-map-element contains() left u={got.get('u')!r}"
    )
    marked = {**marked, "u": {"S": "map-exact"}}

    # --- NS: contains() matches a Number Set member by exact value ---
    update("#nums", {"N": "20"}, "ns-member")
    got = read()
    assert got["u"] == {"S": "ns-member"}, (
        f"UpdateItem under a holding NS-member contains() left u={got.get('u')!r}"
    )
    marked = {**marked, "u": {"S": "ns-member"}}

    # --- BS: contains() matches a Binary Set member by exact value ---
    update("#blobs", {"B": b"\x02"}, "bs-member")
    got = read()
    assert got["u"] == {"S": "bs-member"}, (
        f"UpdateItem under a holding BS-member contains() left u={got.get('u')!r}"
    )
    marked = {**marked, "u": {"S": "bs-member"}}

    # --- SS: a substring of a member is not a member; the exact member is ---
    expect_error(lambda: update("#codes", {"S": "admin"}, "ss-substring"), *_COND_FAILED)
    got = read()
    assert got == marked, f"UpdateItem under a failing SS-substring contains() left {got!r}"

    update("#codes", {"S": "alpha-admin"}, "ss-exact")
    got = read()
    assert got["u"] == {"S": "ss-exact"}, (
        f"UpdateItem under a holding SS-member contains() left u={got.get('u')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
