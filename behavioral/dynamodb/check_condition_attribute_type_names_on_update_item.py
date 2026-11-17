"""condition-attribute-type-names-on-update-item."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-attribute-type-names-on-update-item"
GROUP = "conditions"
SERVICES = ["dynamodb"]

_COND_FAILED = ("ConditionalCheckFailedException", "The conditional request failed")


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


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem's ConditionExpression attribute_type matches the stored type for S, N, BOOL,
    NULL, L, M, NS and SS alike when ANDed together in one condition, and a mismatched type name
    refuses the write with the item left unchanged.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-attrtype-upd-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    key = {"pk": {"S": "item"}}
    item = {
        **key,
        "s_attr": {"S": "str"},
        "n_attr": {"N": "5"},
        "bool_attr": {"BOOL": True},
        "null_attr": {"NULL": True},
        "list_attr": {"L": [{"S": "x"}]},
        "m_attr": {"M": {"k": {"S": "v"}}},
        "ns_attr": {"NS": ["1", "2"]},
        "ss_attr": {"SS": ["a", "b"]},
    }
    ddb.put_item(TableName=table, Item=item)

    names = {"#s": "s_attr", "#n": "n_attr", "#b": "bool_attr", "#nu": "null_attr",
             "#l": "list_attr", "#m": "m_attr", "#ns": "ns_attr", "#ss": "ss_attr"}
    condition = (
        "attribute_type(#s, :ts) AND attribute_type(#n, :tn) AND attribute_type(#b, :tb) "
        "AND attribute_type(#nu, :tnu) AND attribute_type(#l, :tl) AND attribute_type(#m, :tm) "
        "AND attribute_type(#ns, :tns) AND attribute_type(#ss, :tss)"
    )
    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET #mk = :v1",
        ExpressionAttributeNames={**names, "#mk": "marker"},
        ExpressionAttributeValues={
            ":ts": {"S": "S"}, ":tn": {"S": "N"}, ":tb": {"S": "BOOL"}, ":tnu": {"S": "NULL"},
            ":tl": {"S": "L"}, ":tm": {"S": "M"}, ":tns": {"S": "NS"}, ":tss": {"S": "SS"},
            ":v1": {"S": "matched"},
        },
        ConditionExpression=condition,
    )
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert got.get("marker") == {"S": "matched"}, (
        f"UpdateItem under a condition ANDing attribute_type over S, N, BOOL, NULL, L, M, NS and "
        f"SS left marker at {got.get('marker')!r}, expected it set to 'matched'"
    )

    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key=key, UpdateExpression="SET #mk = :v2",
            ExpressionAttributeNames={"#mk": "marker", "#n": "n_attr"},
            ExpressionAttributeValues={":v2": {"S": "mismatched"}, ":wrong": {"S": "S"}},
            ConditionExpression="attribute_type(#n, :wrong)",
        ),
        *_COND_FAILED,
    )
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert got.get("marker") == {"S": "matched"}, (
        f"UpdateItem under a mismatched attribute_type condition (n_attr is N, checked against S) "
        f"left marker at {got.get('marker')!r}, expected the earlier 'matched' value unchanged"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
