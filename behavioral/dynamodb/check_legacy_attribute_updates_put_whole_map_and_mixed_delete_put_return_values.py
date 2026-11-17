"""legacy-attribute-updates-put-whole-map-and-mixed-delete-put-return-values."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "legacy-attribute-updates-put-whole-map-and-mixed-delete-put-return-values"
GROUP = "update-expression"
SERVICES = ["dynamodb"]


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
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _s(v):
    return {"S": v}


def _m(**members):
    return {"M": members}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Legacy AttributeUpdates PUT of a whole map with UPDATED_OLD returns the pre-update map, and
    a DELETE mixed with a PUT in one call carries UPDATED_NEW only the PUT's value.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-legacyrv-")
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

    map_key = {"pk": _s("mapitem"), "sk": _s("s1")}
    ddb.put_item(TableName=table, Item={
        **map_key,
        "profile": _m(city=_s("nyc"), note=_s("old")),
    })

    got = ddb.update_item(
        TableName=table, Key=map_key,
        AttributeUpdates={"profile": {"Action": "PUT", "Value": _m(city=_s("sf"))}},
        ReturnValues="UPDATED_OLD",
    ).get("Attributes")
    want_old = {"profile": _m(city=_s("nyc"), note=_s("old"))}
    assert got == want_old, (
        f"legacy PUT of a whole map with UPDATED_OLD returned {got!r}, expected the pre-update map {want_old!r}"
    )
    item = ddb.get_item(TableName=table, Key=map_key, ConsistentRead=True)["Item"]
    assert item.get("profile") == _m(city=_s("sf")), (
        f"after the PUT the stored map is {item.get('profile')!r}, expected it replaced wholesale with city=sf only"
    )

    mix_key = {"pk": _s("mixitem"), "sk": _s("s1")}
    ddb.put_item(TableName=table, Item={**mix_key, "a": _s("a0"), "b": _s("b0")})

    got = ddb.update_item(
        TableName=table, Key=mix_key,
        AttributeUpdates={
            "a": {"Action": "DELETE"},
            "b": {"Action": "PUT", "Value": _s("b1")},
        },
        ReturnValues="UPDATED_NEW",
    ).get("Attributes")
    assert got == {"b": _s("b1")}, (
        f"a DELETE mixed with a PUT in one call, with UPDATED_NEW, returned {got!r}; "
        f"expected only the PUT's new value for 'b', nothing for the deleted 'a'"
    )
    item2 = ddb.get_item(TableName=table, Key=mix_key, ConsistentRead=True)["Item"]
    assert "a" not in item2, f"'a' is still present after its whole-attribute DELETE: {item2.get('a')!r}"
    assert item2.get("b") == _s("b1"), f"final 'b' is {item2.get('b')!r}, expected the PUT's value"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
