"""legacy-attribute-updates-combined-delete-add-set-add-list-on-absent-item."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "legacy-attribute-updates-combined-delete-add-set-add-list-on-absent-item"
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


def _ss(*members):
    return {"SS": list(members)}


def _l(*values):
    return {"L": list(values)}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single legacy AttributeUpdates call against a wholly absent item, combining a no-op
    DELETE with an ADD on a String Set and an ADD on a List, creates the item with only the two
    ADD results, and UPDATED_NEW reports only those two, nothing for the DELETE.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-legacycombo-")
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

    key = {"pk": _s("absent-combo"), "sk": _s("s1")}
    got = ddb.update_item(
        TableName=table, Key=key,
        AttributeUpdates={
            "ghost": {"Action": "DELETE"},
            "tags": {"Action": "ADD", "Value": _ss("x", "y")},
            "hist": {"Action": "ADD", "Value": _l(_s("z"))},
        },
        ReturnValues="UPDATED_NEW",
    ).get("Attributes")
    assert got is not None and set(got.get("tags", {}).get("SS", [])) == {"x", "y"}, (
        f"combined call on an absent item with UPDATED_NEW returned {got!r} for 'tags', expected the ADD set {{x,y}}"
    )
    assert got.get("hist") == _l(_s("z")), (
        f"combined call on an absent item with UPDATED_NEW returned {got.get('hist')!r} for 'hist', "
        f"expected the ADD list [z]"
    )
    assert "ghost" not in got, (
        f"the no-op DELETE must not appear in UPDATED_NEW, got {got!r}"
    )

    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert "ghost" not in item, f"the no-op DELETE must not create 'ghost', found {item.get('ghost')!r}"
    assert set(item.get("tags", {}).get("SS", [])) == {"x", "y"}, (
        f"the created item's 'tags' is {item.get('tags')!r}, expected {{x,y}}"
    )
    assert item.get("hist") == _l(_s("z")), f"the created item's 'hist' is {item.get('hist')!r}, expected [z]"
    assert set(item) == {"pk", "sk", "tags", "hist"}, (
        f"the created item has attributes {sorted(item)}, expected only the key plus the two ADD results"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
