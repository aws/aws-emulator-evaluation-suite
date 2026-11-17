"""update-item-many-clause-combo-updated-new-omits-out-of-bounds-list-append."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-many-clause-combo-updated-new-omits-out-of-bounds-list-append"
GROUP = "update-expression"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises."""
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


def _n(v):
    return {"N": v}


def _s(v):
    return {"S": v}


_EXPR = (
    "SET a[0] = a[0] + :inc, a[9] = :append ADD info.visits :one REMOVE info.tmp DELETE tags :rm"
)
_VALUES = {
    ":inc": _n("5"),
    ":append": _n("100"),
    ":one": _n("1"),
    ":rm": {"SS": ["alpha"]},
}


def _seed(ddb, table, pk):
    key = {"pk": _s(pk)}
    ddb.put_item(TableName=table, Item={
        **key,
        "a": {"L": [_n("1"), _n("2")]},
        "info": {"M": {"visits": _n("5"), "tmp": _s("old")}},
        "tags": {"SS": ["alpha", "beta", "gamma"]},
    })
    return key


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """One UpdateExpression combining SET on in-bounds and out-of-bounds list indices, ADD on a
    nested map number, REMOVE of a nested map key and DELETE from a string set applies every
    clause; UPDATED_NEW omits the out-of-bounds append entirely, even though it is stored.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-combo-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    # ALL_NEW over the whole combo proves every clause actually applied: a[0] += 5 and a[9]
    # (past the end) appends 100 at index 2; info.visits += 1 and info.tmp is gone; "alpha"
    # left the string set.
    key1 = _seed(ddb, table, "combo-all-new")
    got = ddb.update_item(TableName=table, Key=key1, UpdateExpression=_EXPR,
                          ExpressionAttributeValues=_VALUES, ReturnValues="ALL_NEW")["Attributes"]
    want = {
        **key1,
        "a": {"L": [_n("6"), _n("2"), _n("100")]},
        "info": {"M": {"visits": _n("6")}},
        "tags": {"SS": ["beta", "gamma"]},
    }
    assert got == want, f"ALL_NEW after the many-clause combo returned {got!r}, expected {want!r}"
    item = ddb.get_item(TableName=table, Key=key1, ConsistentRead=True)["Item"]
    assert item == want, f"stored item after the many-clause combo is {item!r}, expected {want!r}"

    # The identical combo against an identical fresh item, read back with UPDATED_NEW instead:
    # the in-bounds a[0] SET shows up as a one-element list holding only its own new value,
    # the out-of-bounds a[9] append is not in "a" at all, REMOVE never appears, and ADD/DELETE
    # show their usual new leaves.
    key2 = _seed(ddb, table, "combo-updated-new")
    got = ddb.update_item(TableName=table, Key=key2, UpdateExpression=_EXPR,
                          ExpressionAttributeValues=_VALUES, ReturnValues="UPDATED_NEW")["Attributes"]
    want_updated_new = {
        "a": {"L": [_n("6")]},
        "info": {"M": {"visits": _n("6")}},
        "tags": {"SS": ["beta", "gamma"]},
    }
    assert got == want_updated_new, (
        f"UPDATED_NEW after the many-clause combo returned {got!r}, expected {want_updated_new!r} "
        f"(the out-of-bounds append must be absent from 'a')"
    )

    # The out-of-bounds append is nonetheless persisted: a later read shows the full three-element
    # list, matching the ALL_NEW case exactly.
    final = ddb.get_item(TableName=table, Key=key2, ConsistentRead=True)["Item"]
    want_final = {
        **key2,
        "a": {"L": [_n("6"), _n("2"), _n("100")]},
        "info": {"M": {"visits": _n("6")}},
        "tags": {"SS": ["beta", "gamma"]},
    }
    assert final == want_final, (
        f"stored item after the UPDATED_NEW combo call is {final!r}, expected {want_final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
