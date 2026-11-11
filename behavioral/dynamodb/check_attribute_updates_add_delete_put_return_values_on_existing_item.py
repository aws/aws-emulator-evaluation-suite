"""attribute-updates-add-delete-put-return-values-on-existing-item."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attribute-updates-add-delete-put-return-values-on-existing-item"
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


def _n(v):
    return {"N": v}


def _ss(*members):
    return {"SS": list(members)}


def _l(*values):
    return {"L": list(values)}


def _m(**members):
    return {"M": members}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Legacy AttributeUpdates ADD unions a set with duplicates dropped and appends to a list;
    DELETE with a Value removes one set member, DELETE with none removes the whole attribute,
    and PUT replaces a map wholesale rather than merging it, each shown through UPDATED_NEW/OLD.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-attrupd-")
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

    key = {"pk": _s("item1"), "sk": _s("s1")}
    ddb.put_item(TableName=table, Item={
        **key,
        "counter": _n("10"),
        "tags": _ss("a", "b"),
        "hist": _l(_s("x")),
        "profile": _m(city=_s("nyc"), note=_s("old")),
    })

    def upd(attribute_updates, rv):
        return ddb.update_item(TableName=table, Key=key, AttributeUpdates=attribute_updates,
                               ReturnValues=rv).get("Attributes")

    got = upd({"counter": {"Action": "ADD", "Value": _n("5")}}, "UPDATED_NEW")
    assert got == {"counter": _n("15")}, f"ADD counter +5 with UPDATED_NEW returned {got!r}"

    got = upd({"counter": {"Action": "ADD", "Value": _n("3")}}, "UPDATED_OLD")
    assert got == {"counter": _n("15")}, f"ADD counter +3 with UPDATED_OLD returned {got!r}, expected the pre-update 15"

    got = upd({"tags": {"Action": "ADD", "Value": _ss("b", "c")}}, "UPDATED_NEW")
    assert got is not None and set(got["tags"]["SS"]) == {"a", "b", "c"} and len(got["tags"]["SS"]) == 3, (
        f"ADD tags {{b,c}} onto existing {{a,b}} with UPDATED_NEW returned {got!r}, "
        f"expected the union {{a,b,c}} with the duplicate 'b' dropped"
    )

    got = upd({"hist": {"Action": "ADD", "Value": _l(_s("z"))}}, "UPDATED_NEW")
    assert got == {"hist": _l(_s("x"), _s("z"))}, (
        f"ADD a one-element list onto an existing list with UPDATED_NEW returned {got!r}, expected the element appended"
    )

    got = upd({"tags": {"Action": "DELETE", "Value": _ss("a")}}, "UPDATED_OLD")
    assert got is not None and set(got["tags"]["SS"]) == {"a", "b", "c"}, (
        f"DELETE of set member 'a' with UPDATED_OLD returned {got!r}, expected the pre-delete set {{a,b,c}}"
    )

    got = upd({"profile": {"Action": "PUT", "Value": _m(city=_s("sf"))}}, "UPDATED_NEW")
    assert got == {"profile": _m(city=_s("sf"))}, (
        f"PUT of a whole map with UPDATED_NEW returned {got!r}, expected the map replaced wholesale "
        f"with no 'note' carried over from before"
    )

    got = upd({"hist": {"Action": "DELETE"}}, "UPDATED_OLD")
    assert got == {"hist": _l(_s("x"), _s("z"))}, (
        f"DELETE of the whole 'hist' attribute with UPDATED_OLD returned {got!r}, expected its pre-delete value"
    )

    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert item.get("counter") == _n("18"), f"final counter is {item.get('counter')!r}, expected 18"
    assert set(item.get("tags", {}).get("SS", [])) == {"b", "c"}, (
        f"final tags are {item.get('tags')!r}, expected {{b,c}} after the member delete"
    )
    assert item.get("profile") == _m(city=_s("sf")), f"final profile is {item.get('profile')!r}, expected city=sf only"
    assert "hist" not in item, f"'hist' is still present after its whole-attribute DELETE: {item.get('hist')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
