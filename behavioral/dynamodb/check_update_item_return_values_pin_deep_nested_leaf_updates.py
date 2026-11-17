"""update-item-return-values-pin-deep-nested-leaf-updates."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-return-values-pin-deep-nested-leaf-updates"
GROUP = "expressions"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found, timeout_s=300.0):
    """Run undo() where a failed delete raises; ResourceInUse is retried to the deadline."""
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


def _wait_active(ddb, table, timeout_s=300.0):
    """Poll DescribeTable every 2 s until ACTIVE, or fail with the last status read."""
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem ReturnValues after a deep (map-leaf, list-index) update: ALL_NEW/ALL_OLD still
    pin the whole item, UPDATED_NEW omits Attributes on a REMOVE, and UPDATED_OLD rebuilds the
    touched nested map leaf and list under their parent attribute rather than flattening the path.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-rvdeep-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)

    key = {"pk": {"S": "rv-deep"}}
    item = {
        **key,
        "deep": {"M": {"leaf": {"N": "1"}, "extra": {"S": "x"}}},
        "lst": {"L": [{"S": "a0"}, {"S": "a1"}, {"S": "a2"}]},
        "side": {"S": "keep"},
    }
    ddb.put_item(TableName=table, Item=item)

    # ALL_NEW after a deep map-leaf SET pins the WHOLE item, not just the touched leaf.
    resp = ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET deep.leaf = :v",
        ExpressionAttributeValues={":v": {"N": "2"}},
        ReturnValues="ALL_NEW",
    )
    after_set1 = {**item, "deep": {"M": {"leaf": {"N": "2"}, "extra": {"S": "x"}}}}
    assert resp["Attributes"] == after_set1, (
        f"ALL_NEW after a deep SET must return the whole item with the leaf updated, "
        f"got {resp['Attributes']!r}, expected {after_set1!r}"
    )

    # ALL_OLD after a second deep map-leaf SET pins the WHOLE prior item.
    resp = ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET deep.leaf = :v",
        ExpressionAttributeValues={":v": {"N": "3"}},
        ReturnValues="ALL_OLD",
    )
    assert resp["Attributes"] == after_set1, (
        f"ALL_OLD after a deep SET must return the whole prior item, "
        f"got {resp['Attributes']!r}, expected {after_set1!r}"
    )
    after_set2 = {**after_set1, "deep": {"M": {"leaf": {"N": "3"}, "extra": {"S": "x"}}}}
    current = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert current == after_set2, (
        f"the second deep SET must have applied, got {current!r}, expected {after_set2!r}"
    )

    # UPDATED_NEW after a nested-leaf REMOVE omits Attributes entirely (REMOVE has no new value).
    resp = ddb.update_item(TableName=table, Key=key, UpdateExpression="REMOVE deep.extra",
                           ReturnValues="UPDATED_NEW")
    assert "Attributes" not in resp, (
        f"UPDATED_NEW after REMOVE of a nested map leaf must omit Attributes, got {resp.get('Attributes')!r}"
    )
    after_remove_extra = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after_remove_extra == {**after_set2, "deep": {"M": {"leaf": {"N": "3"}}}}, (
        f"REMOVE deep.extra must take effect, got {after_remove_extra!r}"
    )

    # UPDATED_OLD after a nested-leaf REMOVE returns the removed leaf rebuilt under its parent
    # attribute, not the flat path, and not the whole item.
    resp = ddb.update_item(TableName=table, Key=key, UpdateExpression="REMOVE deep.leaf",
                           ReturnValues="UPDATED_OLD")
    assert resp["Attributes"] == {"deep": {"M": {"leaf": {"N": "3"}}}}, (
        f"UPDATED_OLD after REMOVE of a nested map leaf must rebuild {{deep: {{leaf: <old>}}}} "
        f"under its parent, got {resp['Attributes']!r}"
    )
    after_remove_leaf = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after_remove_leaf["deep"] == {"M": {}}, (
        f"both deep.extra and deep.leaf must now be gone, got {after_remove_leaf['deep']!r}"
    )

    # UPDATED_OLD after REMOVE of a list INDEX returns only the removed element, rebuilt as a
    # one-element list under its parent attribute's own name.
    resp = ddb.update_item(TableName=table, Key=key, UpdateExpression="REMOVE lst[1]",
                           ReturnValues="UPDATED_OLD")
    assert resp["Attributes"] == {"lst": {"L": [{"S": "a1"}]}}, (
        f"UPDATED_OLD after REMOVE of a list index must return the removed element alone, "
        f"rebuilt under its list attribute's name, got {resp['Attributes']!r}"
    )
    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert final["lst"] == {"L": [{"S": "a0"}, {"S": "a2"}]}, (
        f"REMOVE lst[1] must drop exactly index 1, got {final['lst']!r}"
    )
    assert final["side"] == {"S": "keep"}, f"the untouched sibling attribute must survive, got {final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
