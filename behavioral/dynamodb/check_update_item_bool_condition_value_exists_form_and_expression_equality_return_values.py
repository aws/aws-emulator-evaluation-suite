"""update-item-bool-condition-value-exists-form-and-expression-equality-return-values."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-bool-condition-value-exists-form-and-expression-equality-return-values"
GROUP = "conditions"
SERVICES = ["dynamodb"]
_ERR_CCFE = ("ConditionalCheckFailedException", "The conditional request failed")


def _code_and_message(fn) -> tuple[str, str]:
    """The botocore error code and message *fn* raises.

    An unexpected success raises rather than returning a falsy pair.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _expect_error(fn, code: str, message: str) -> None:
    got = _code_and_message(fn)
    assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem's legacy Expected implicit Value form, its explicit Exists+Value form, and a
    ConditionExpression equality all gate on a BOOL attribute the same way; a passing
    ConditionExpression equality returns UPDATED_NEW's post-update BOOL, not the pre-update one.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.Expected.html
    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(TableName=table, KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                      AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                      BillingMode="PAY_PER_REQUEST", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 60})

    def _read(pk: str):
        return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")

    # --- legacy Expected, implicit Value form: no ComparisonOperator, no Exists, so AWS treats
    # the attribute as required to exist and equal Value. ---
    ddb.put_item(TableName=table, Item={"pk": {"S": "implicit-match"}, "flag": {"BOOL": True}})
    ddb.update_item(TableName=table, Key={"pk": {"S": "implicit-match"}},
                     AttributeUpdates={"marker": {"Value": {"S": "applied"}, "Action": "PUT"}},
                     Expected={"flag": {"Value": {"BOOL": True}}})
    got = _read("implicit-match")
    assert got == {"pk": {"S": "implicit-match"}, "flag": {"BOOL": True}, "marker": {"S": "applied"}}, (
        f"implicit Value-form match must let the write land, got {got!r}")

    ddb.put_item(TableName=table, Item={"pk": {"S": "implicit-mismatch"}, "flag": {"BOOL": False}})
    _expect_error(lambda: ddb.update_item(
        TableName=table, Key={"pk": {"S": "implicit-mismatch"}},
        AttributeUpdates={"marker": {"Value": {"S": "applied"}, "Action": "PUT"}},
        Expected={"flag": {"Value": {"BOOL": True}}}), *_ERR_CCFE)
    got = _read("implicit-mismatch")
    assert got == {"pk": {"S": "implicit-mismatch"}, "flag": {"BOOL": False}}, (
        f"a rejected implicit Value-form UpdateItem must leave the item unchanged, got {got!r}")

    # --- legacy Expected, explicit Exists+Value form on BOOL. ---
    ddb.put_item(TableName=table, Item={"pk": {"S": "explicit-match"}, "flag": {"BOOL": False}})
    ddb.update_item(TableName=table, Key={"pk": {"S": "explicit-match"}},
                     AttributeUpdates={"marker": {"Value": {"S": "applied"}, "Action": "PUT"}},
                     Expected={"flag": {"Exists": True, "Value": {"BOOL": False}}})
    got = _read("explicit-match")
    assert got == {"pk": {"S": "explicit-match"}, "flag": {"BOOL": False}, "marker": {"S": "applied"}}, (
        f"explicit Exists+Value match must let the write land, got {got!r}")

    ddb.put_item(TableName=table, Item={"pk": {"S": "explicit-mismatch"}, "flag": {"BOOL": True}})
    _expect_error(lambda: ddb.update_item(
        TableName=table, Key={"pk": {"S": "explicit-mismatch"}},
        AttributeUpdates={"marker": {"Value": {"S": "applied"}, "Action": "PUT"}},
        Expected={"flag": {"Exists": True, "Value": {"BOOL": False}}}), *_ERR_CCFE)
    got = _read("explicit-mismatch")
    assert got == {"pk": {"S": "explicit-mismatch"}, "flag": {"BOOL": True}}, (
        f"a rejected explicit Exists+Value UpdateItem must leave the item unchanged, got {got!r}")

    # --- ConditionExpression equality on BOOL, gating a SET that flips the same attribute:
    # UPDATED_NEW must carry the post-update BOOL, not the precondition's BOOL. ---
    ddb.put_item(TableName=table, Item={"pk": {"S": "expr-match"}, "flag": {"BOOL": True}})
    resp = ddb.update_item(TableName=table, Key={"pk": {"S": "expr-match"}},
                            UpdateExpression="SET flag = :new",
                            ConditionExpression="flag = :cond",
                            ExpressionAttributeValues={":new": {"BOOL": False}, ":cond": {"BOOL": True}},
                            ReturnValues="UPDATED_NEW")
    assert resp["Attributes"] == {"flag": {"BOOL": False}}, (
        f"UPDATED_NEW after a passing BOOL equality condition must carry the new BOOL, got {resp['Attributes']!r}")
    got = _read("expr-match")
    assert got == {"pk": {"S": "expr-match"}, "flag": {"BOOL": False}}, (
        f"a passing ConditionExpression equality on BOOL did not land, got {got!r}")

    ddb.put_item(TableName=table, Item={"pk": {"S": "expr-mismatch"}, "flag": {"BOOL": False}})
    _expect_error(lambda: ddb.update_item(
        TableName=table, Key={"pk": {"S": "expr-mismatch"}},
        UpdateExpression="SET flag = :new",
        ConditionExpression="flag = :cond",
        ExpressionAttributeValues={":new": {"BOOL": True}, ":cond": {"BOOL": True}},
        ReturnValues="UPDATED_NEW"), *_ERR_CCFE)
    got = _read("expr-mismatch")
    assert got == {"pk": {"S": "expr-mismatch"}, "flag": {"BOOL": False}}, (
        f"a rejected ConditionExpression equality on BOOL must leave the item unchanged, got {got!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
