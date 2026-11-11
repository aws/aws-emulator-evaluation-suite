"""attribute-updates-add-delete-on-absent-item."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attribute-updates-add-delete-on-absent-item"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Legacy AttributeUpdates ADD against a wholly absent item starts the attribute from zero
    and creates the item with only the key and that attribute; DELETE, with or without a Value,
    against a wholly absent item is a no-op that never creates the item.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-attrupdabsent-")
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

    add_key = {"pk": _s("absent-add"), "sk": _s("s1")}
    resp = ddb.update_item(TableName=table, Key=add_key,
                           AttributeUpdates={"counter": {"Action": "ADD", "Value": _n("7")}},
                           ReturnValues="UPDATED_NEW")
    assert resp.get("Attributes") == {"counter": _n("7")}, (
        f"ADD counter +7 against an absent item with UPDATED_NEW returned {resp.get('Attributes')!r}, "
        f"expected it to start from zero"
    )
    item = ddb.get_item(TableName=table, Key=add_key, ConsistentRead=True).get("Item")
    assert item == {**add_key, "counter": _n("7")}, (
        f"the item ADD created is {item!r}, expected only the key plus counter=7"
    )

    delete_key = {"pk": _s("absent-delete"), "sk": _s("s1")}
    resp = ddb.update_item(TableName=table, Key=delete_key,
                           AttributeUpdates={"ghost": {"Action": "DELETE"}},
                           ReturnValues="UPDATED_OLD")
    assert "Attributes" not in resp, (
        f"whole-attribute DELETE against an absent item with UPDATED_OLD returned {resp.get('Attributes')!r}"
    )
    item = ddb.get_item(TableName=table, Key=delete_key, ConsistentRead=True).get("Item")
    assert item is None, f"whole-attribute DELETE against an absent item created {item!r}; expected no item"

    delete_set_key = {"pk": _s("absent-delete-set"), "sk": _s("s1")}
    resp = ddb.update_item(TableName=table, Key=delete_set_key,
                           AttributeUpdates={"tags": {"Action": "DELETE", "Value": _ss("x")}},
                           ReturnValues="UPDATED_NEW")
    assert "Attributes" not in resp, (
        f"set-member DELETE against an absent item with UPDATED_NEW returned {resp.get('Attributes')!r}"
    )
    item = ddb.get_item(TableName=table, Key=delete_set_key, ConsistentRead=True).get("Item")
    assert item is None, f"set-member DELETE against an absent item created {item!r}; expected no item"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
