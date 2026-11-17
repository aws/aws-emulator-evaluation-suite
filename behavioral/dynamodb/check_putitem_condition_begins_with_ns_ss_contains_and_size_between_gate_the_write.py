"""putitem-condition-begins-with-ns-ss-contains-and-size-between-gate-the-write."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "putitem-condition-begins-with-ns-ss-contains-and-size-between-gate-the-write"
GROUP = "expressions"
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


def _unordered(item):
    """``item`` with each top-level set's members sorted; DynamoDB sets carry no member order."""
    if item is None:
        return None
    return {
        name: {kind: sorted(members)} if kind in ("SS", "NS", "BS") else {kind: members}
        for name, value in item.items() for kind, members in value.items()
    }


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutItem ConditionExpression of begins_with on a string, contains() on an NS or SS set,
    or size() BETWEEN bounds is refused with ConditionalCheckFailedException, item unchanged,
    when the function evaluates false, and applies the write, item replaced, when it is true.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-putcond-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # --- begins_with on a string attribute ---
    bw_key = {"pk": {"S": "begins-with-target"}}
    bw_initial = {**bw_key, "code": {"S": "orders-2024"}}
    ddb.put_item(TableName=table, Item=bw_initial)

    expect_error(
        lambda: ddb.put_item(
            TableName=table, Item={**bw_key, "code": {"S": "orders-2024"}, "written": {"BOOL": True}},
            ConditionExpression="begins_with(#c, :p)",
            ExpressionAttributeNames={"#c": "code"}, ExpressionAttributeValues={":p": {"S": "invoices"}},
        ),
        *_COND_FAILED,
    )
    unchanged = ddb.get_item(TableName=table, Key=bw_key, ConsistentRead=True)["Item"]
    assert unchanged == bw_initial, f"PutItem under a failing begins_with() condition left {unchanged!r}, expected {bw_initial!r} unchanged"

    ddb.put_item(
        TableName=table, Item={**bw_key, "code": {"S": "orders-2024"}, "written": {"BOOL": True}},
        ConditionExpression="begins_with(#c, :p)",
        ExpressionAttributeNames={"#c": "code"}, ExpressionAttributeValues={":p": {"S": "orders"}},
    )
    replaced = ddb.get_item(TableName=table, Key=bw_key, ConsistentRead=True)["Item"]
    bw_expected = {**bw_key, "code": {"S": "orders-2024"}, "written": {"BOOL": True}}
    assert replaced == bw_expected, f"PutItem under a holding begins_with() condition left {replaced!r}, expected {bw_expected!r}"

    # --- contains() on a number set (NS) ---
    ns_key = {"pk": {"S": "ns-contains-target"}}
    ns_initial = {**ns_key, "codes": {"NS": ["10", "25", "40"]}}
    ddb.put_item(TableName=table, Item=ns_initial)

    expect_error(
        lambda: ddb.put_item(
            TableName=table, Item={**ns_key, "codes": {"NS": ["10", "25", "40"]}, "written": {"BOOL": True}},
            ConditionExpression="contains(#n, :v)",
            ExpressionAttributeNames={"#n": "codes"}, ExpressionAttributeValues={":v": {"N": "99"}},
        ),
        *_COND_FAILED,
    )
    unchanged = ddb.get_item(TableName=table, Key=ns_key, ConsistentRead=True)["Item"]
    assert _unordered(unchanged) == _unordered(ns_initial), f"PutItem under a failing NS contains() condition left {unchanged!r}, expected {ns_initial!r} unchanged"

    ddb.put_item(
        TableName=table, Item={**ns_key, "codes": {"NS": ["10", "25", "40"]}, "written": {"BOOL": True}},
        ConditionExpression="contains(#n, :v)",
        ExpressionAttributeNames={"#n": "codes"}, ExpressionAttributeValues={":v": {"N": "25"}},
    )
    replaced = ddb.get_item(TableName=table, Key=ns_key, ConsistentRead=True)["Item"]
    ns_expected = {**ns_key, "codes": {"NS": ["10", "25", "40"]}, "written": {"BOOL": True}}
    assert _unordered(replaced) == _unordered(ns_expected), f"PutItem under a holding NS contains() condition left {replaced!r}, expected {ns_expected!r}"

    # --- contains() on a string set (SS) ---
    ss_key = {"pk": {"S": "ss-contains-target"}}
    ss_initial = {**ss_key, "tags": {"SS": ["alpha", "beta"]}}
    ddb.put_item(TableName=table, Item=ss_initial)

    expect_error(
        lambda: ddb.put_item(
            TableName=table, Item={**ss_key, "tags": {"SS": ["alpha", "beta"]}, "written": {"BOOL": True}},
            ConditionExpression="contains(#t, :v)",
            ExpressionAttributeNames={"#t": "tags"}, ExpressionAttributeValues={":v": {"S": "gamma"}},
        ),
        *_COND_FAILED,
    )
    unchanged = ddb.get_item(TableName=table, Key=ss_key, ConsistentRead=True)["Item"]
    assert _unordered(unchanged) == _unordered(ss_initial), f"PutItem under a failing SS contains() condition left {unchanged!r}, expected {ss_initial!r} unchanged"

    ddb.put_item(
        TableName=table, Item={**ss_key, "tags": {"SS": ["alpha", "beta"]}, "written": {"BOOL": True}},
        ConditionExpression="contains(#t, :v)",
        ExpressionAttributeNames={"#t": "tags"}, ExpressionAttributeValues={":v": {"S": "beta"}},
    )
    replaced = ddb.get_item(TableName=table, Key=ss_key, ConsistentRead=True)["Item"]
    ss_expected = {**ss_key, "tags": {"SS": ["alpha", "beta"]}, "written": {"BOOL": True}}
    assert _unordered(replaced) == _unordered(ss_expected), f"PutItem under a holding SS contains() condition left {replaced!r}, expected {ss_expected!r}"

    # --- size(string) BETWEEN bounds ---
    sz_key = {"pk": {"S": "size-between-target"}}
    sz_initial = {**sz_key, "label": {"S": "midsize"}}
    ddb.put_item(TableName=table, Item=sz_initial)

    expect_error(
        lambda: ddb.put_item(
            TableName=table, Item={**sz_key, "label": {"S": "midsize"}, "written": {"BOOL": True}},
            ConditionExpression="size(#l) BETWEEN :lo AND :hi",
            ExpressionAttributeNames={"#l": "label"},
            ExpressionAttributeValues={":lo": {"N": "10"}, ":hi": {"N": "20"}},
        ),
        *_COND_FAILED,
    )
    unchanged = ddb.get_item(TableName=table, Key=sz_key, ConsistentRead=True)["Item"]
    assert unchanged == sz_initial, f"PutItem under a failing size() BETWEEN condition left {unchanged!r}, expected {sz_initial!r} unchanged"

    ddb.put_item(
        TableName=table, Item={**sz_key, "label": {"S": "midsize"}, "written": {"BOOL": True}},
        ConditionExpression="size(#l) BETWEEN :lo AND :hi",
        ExpressionAttributeNames={"#l": "label"},
        ExpressionAttributeValues={":lo": {"N": "3"}, ":hi": {"N": "10"}},
    )
    replaced = ddb.get_item(TableName=table, Key=sz_key, ConsistentRead=True)["Item"]
    sz_expected = {**sz_key, "label": {"S": "midsize"}, "written": {"BOOL": True}}
    assert replaced == sz_expected, f"PutItem under a holding size() BETWEEN condition left {replaced!r}, expected {sz_expected!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
