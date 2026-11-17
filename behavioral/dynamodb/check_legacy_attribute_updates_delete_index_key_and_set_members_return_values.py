"""legacy-attribute-updates-delete-index-key-and-set-members-return-values."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "legacy-attribute-updates-delete-index-key-and-set-members-return-values"
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
    """Poll DescribeTable every 2 s until the table and its index are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        gsis = desc.get("GlobalSecondaryIndexes", [])
        if desc["TableStatus"] == "ACTIVE" and all(g["IndexStatus"] == "ACTIVE" for g in gsis):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _s(v):
    return {"S": v}


def _ss(*members):
    return {"SS": list(members)}


def _gsi_count(ddb, table, index, key_name, value):
    resp = ddb.query(
        TableName=table, IndexName=index,
        KeyConditionExpression="#k = :v",
        ExpressionAttributeNames={"#k": key_name},
        ExpressionAttributeValues={":v": value},
    )
    return resp["Count"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a hash+range table, legacy DELETE of a GSI key attribute carries UPDATED_NEW empty and
    drops the item from the index; DELETE of some set members carries UPDATED_NEW with the
    remaining members, and DELETE of the last members carries it empty and drops the attribute.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-legacyidx-")
    index = "gsi1idx"
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gsi1", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": index,
            "KeySchema": [{"AttributeName": "gsi1", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    idx_key = {"pk": _s("idx1"), "sk": _s("s1")}
    gsi_value = _s("g1")
    ddb.put_item(TableName=table, Item={**idx_key, "gsi1": gsi_value, "other": _s("o0")})
    deadline = time.monotonic() + 60.0
    before = _gsi_count(ddb, table, index, "gsi1", gsi_value)
    while before != 1 and time.monotonic() < deadline:
        time.sleep(2)
        before = _gsi_count(ddb, table, index, "gsi1", gsi_value)
    assert before == 1, f"the item must be visible through the index before the delete, saw count {before}"

    got = ddb.update_item(
        TableName=table, Key=idx_key,
        AttributeUpdates={"gsi1": {"Action": "DELETE"}},
        ReturnValues="UPDATED_NEW",
    ).get("Attributes")
    assert not got, (
        f"legacy DELETE of an index-key attribute carries UPDATED_NEW {got!r}, expected nothing "
        f"(DELETE has no new value)"
    )
    item = ddb.get_item(TableName=table, Key=idx_key, ConsistentRead=True)["Item"]
    assert "gsi1" not in item, f"the index-key attribute is still present after DELETE: {item.get('gsi1')!r}"
    assert item.get("other") == _s("o0"), f"the rest of the item must be untouched, got {item!r}"

    deadline = time.monotonic() + 60.0
    after = _gsi_count(ddb, table, index, "gsi1", gsi_value)
    while after != 0 and time.monotonic() < deadline:
        time.sleep(2)
        after = _gsi_count(ddb, table, index, "gsi1", gsi_value)
    assert after == 0, f"the item must disappear from the index once its key attribute is deleted, saw count {after}"

    set_key = {"pk": _s("setitem"), "sk": _s("s1")}
    ddb.put_item(TableName=table, Item={**set_key, "tags": _ss("a", "b", "c")})

    got = ddb.update_item(
        TableName=table, Key=set_key,
        AttributeUpdates={"tags": {"Action": "DELETE", "Value": _ss("a")}},
        ReturnValues="UPDATED_NEW",
    ).get("Attributes")
    assert got is not None and set(got.get("tags", {}).get("SS", [])) == {"b", "c"}, (
        f"legacy DELETE of one set member with UPDATED_NEW returned {got!r}, expected the remaining {{b,c}}"
    )
    item2 = ddb.get_item(TableName=table, Key=set_key, ConsistentRead=True)["Item"]
    assert set(item2.get("tags", {}).get("SS", [])) == {"b", "c"}, (
        f"after the one-member delete the stored set is {item2.get('tags')!r}, expected {{b,c}}"
    )

    got = ddb.update_item(
        TableName=table, Key=set_key,
        AttributeUpdates={"tags": {"Action": "DELETE", "Value": _ss("b", "c")}},
        ReturnValues="UPDATED_NEW",
    ).get("Attributes")
    assert not got, (
        f"legacy DELETE of a set's last members carries UPDATED_NEW {got!r}, expected nothing "
        f"(the attribute is gone, DELETE has no new value)"
    )
    item3 = ddb.get_item(TableName=table, Key=set_key, ConsistentRead=True)["Item"]
    assert "tags" not in item3, f"'tags' must be gone after its last members are deleted, found {item3.get('tags')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
