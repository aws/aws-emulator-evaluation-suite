"""update-item-if-not-exists-document-path-fallback-and-existing-subtract."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-if-not-exists-document-path-fallback-and-existing-subtract"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_TABLE_ACTIVE_BUDGET_S = 120.0
_TEARDOWN_WAIT_S = 120.0


def _delete_table_when_possible(ddb, table_name):
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise RuntimeError(
                f"dynamodb table {table_name!r} could not be deleted: {code}"
            ) from exc


def _create_table(ctx, ddb):
    name = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_when_possible(ddb, name))
    deadline = time.monotonic() + _TABLE_ACTIVE_BUDGET_S
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return name
        time.sleep(2.0)
    raise AssertionError(f"table {name!r} not ACTIVE within {_TABLE_ACTIVE_BUDGET_S}s: {status!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """`SET b = if_not_exists(b, a)` copies a document path's value, key attribute included,
    into an absent `b` and leaves a present `b` untouched; `SET v = if_not_exists(v, :d) - :amt`
    subtracts from the existing `v`, ignoring the default, which only an absent `v` falls back to.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)

    # b absent: if_not_exists(b, a) copies the value at document path `a`.
    key1 = {"pk": {"S": "row-copy-attr"}}
    ddb.put_item(TableName=table, Item={**key1, "a": {"S": "source-value"}})
    r1 = ddb.update_item(
        TableName=table, Key=key1, UpdateExpression="SET b = if_not_exists(b, a)",
        ReturnValues="ALL_NEW",
    )["Attributes"]
    assert r1 == {**key1, "a": {"S": "source-value"}, "b": {"S": "source-value"}}, (
        f"if_not_exists(b, a) with b absent returned {r1!r}, expected b copied from a"
    )

    # b now present: a second if_not_exists(b, a) keeps b, even after `a` changes.
    ddb.update_item(
        TableName=table, Key=key1, UpdateExpression="SET a = :changed",
        ExpressionAttributeValues={":changed": {"S": "changed-value"}},
    )
    r2 = ddb.update_item(
        TableName=table, Key=key1, UpdateExpression="SET b = if_not_exists(b, a)",
        ReturnValues="ALL_NEW",
    )["Attributes"]
    assert r2 == {**key1, "a": {"S": "changed-value"}, "b": {"S": "source-value"}}, (
        f"if_not_exists(b, a) with b already present returned {r2!r}, expected b to stay "
        f"'source-value' and not be overwritten by the changed 'a'"
    )

    # b absent, operand is the key attribute itself: if_not_exists(b, pk) copies the key's value.
    key2 = {"pk": {"S": "row-copy-key"}}
    ddb.put_item(TableName=table, Item=dict(key2))
    r3 = ddb.update_item(
        TableName=table, Key=key2, UpdateExpression="SET b = if_not_exists(b, pk)",
        ReturnValues="ALL_NEW",
    )["Attributes"]
    assert r3 == {**key2, "b": {"S": "row-copy-key"}}, (
        f"if_not_exists(b, pk) with b absent returned {r3!r}, expected b copied from the key "
        f"attribute pk"
    )

    # v present: if_not_exists(v, :d) - :amt subtracts :amt from the EXISTING v, ignoring :d.
    key3 = {"pk": {"S": "row-subtract-existing"}}
    ddb.put_item(TableName=table, Item={**key3, "v": {"N": "10"}})
    r4 = ddb.update_item(
        TableName=table, Key=key3, UpdateExpression="SET v = if_not_exists(v, :d) - :amt",
        ExpressionAttributeValues={":d": {"N": "100"}, ":amt": {"N": "3"}},
        ReturnValues="ALL_NEW",
    )["Attributes"]
    assert r4 == {**key3, "v": {"N": "7"}}, (
        f"if_not_exists(v, :d) - :amt with v=10 stored returned {r4!r}, expected v=7 "
        f"(10 - 3, the default 100 must be ignored)"
    )

    # Contrast: v absent falls back to the default itself, then subtracts :amt from it.
    key4 = {"pk": {"S": "row-subtract-default"}}
    ddb.put_item(TableName=table, Item=dict(key4))
    r5 = ddb.update_item(
        TableName=table, Key=key4, UpdateExpression="SET v = if_not_exists(v, :d) - :amt",
        ExpressionAttributeValues={":d": {"N": "100"}, ":amt": {"N": "3"}},
        ReturnValues="ALL_NEW",
    )["Attributes"]
    assert r5 == {**key4, "v": {"N": "97"}}, (
        f"if_not_exists(v, :d) - :amt with v absent returned {r5!r}, expected v=97 "
        f"(100 - 3, the default standing in for the missing v)"
    )

    final1 = ddb.get_item(TableName=table, Key=key1, ConsistentRead=True)["Item"]
    assert final1 == {**key1, "a": {"S": "changed-value"}, "b": {"S": "source-value"}}, (
        f"final stored row-copy-attr item is {final1!r}"
    )
    final3 = ddb.get_item(TableName=table, Key=key3, ConsistentRead=True)["Item"]
    assert final3 == {**key3, "v": {"N": "7"}}, f"final stored row-subtract-existing item is {final3!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
