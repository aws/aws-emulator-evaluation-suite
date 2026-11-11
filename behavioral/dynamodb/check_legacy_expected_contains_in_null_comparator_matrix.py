"""legacy-expected-contains-in-null-comparator-matrix."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "legacy-expected-contains-in-null-comparator-matrix"
GROUP = "conditions"
SERVICES = ["dynamodb"]
_ERR_CCFE = "ConditionalCheckFailedException"
_ERR_CCFE_MESSAGE = "The conditional request failed"

# (case_name, stored attr value, Expected clause for 'attr', expect the write to land)
CASES = [
    ("contains_substring_true", {"S": "hello world"},
     {"ComparisonOperator": "CONTAINS", "AttributeValueList": [{"S": "world"}]}, True),
    ("contains_substring_false", {"S": "hello world"},
     {"ComparisonOperator": "CONTAINS", "AttributeValueList": [{"S": "xyz"}]}, False),
    ("contains_set_element_true", {"SS": ["x", "y"]},
     {"ComparisonOperator": "CONTAINS", "AttributeValueList": [{"S": "x"}]}, True),
    ("contains_set_element_false", {"SS": ["x", "y"]},
     {"ComparisonOperator": "CONTAINS", "AttributeValueList": [{"S": "z"}]}, False),
    ("not_contains_true", {"S": "hello world"},
     {"ComparisonOperator": "NOT_CONTAINS", "AttributeValueList": [{"S": "xyz"}]}, True),
    ("not_contains_false", {"S": "hello world"},
     {"ComparisonOperator": "NOT_CONTAINS", "AttributeValueList": [{"S": "world"}]}, False),
    ("in_scalar_true", {"S": "b"},
     {"ComparisonOperator": "IN",
      "AttributeValueList": [{"S": "a"}, {"S": "b"}, {"S": "c"}]}, True),
    ("in_scalar_false", {"S": "z"},
     {"ComparisonOperator": "IN",
      "AttributeValueList": [{"S": "a"}, {"S": "b"}, {"S": "c"}]}, False),
    # IN never matches a set attribute: with the element present or absent, the write is
    # ConditionalCheckFailedException.
    ("in_against_set_element_present", {"SS": ["x", "y"]},
     {"ComparisonOperator": "IN", "AttributeValueList": [{"S": "x"}]}, False),
    ("in_against_set_element_absent", {"SS": ["x", "y"]},
     {"ComparisonOperator": "IN", "AttributeValueList": [{"S": "z"}]}, False),
    ("begins_with_false", {"S": "hello"},
     {"ComparisonOperator": "BEGINS_WITH", "AttributeValueList": [{"S": "xyz"}]}, False),
    ("null_true_absent", None,
     {"ComparisonOperator": "NULL"}, True),
    ("null_false_present", {"S": "present"},
     {"ComparisonOperator": "NULL"}, False),
    ("not_null_true_present", {"S": "present"},
     {"ComparisonOperator": "NOT_NULL"}, True),
    ("not_null_false_absent", None,
     {"ComparisonOperator": "NOT_NULL"}, False),
]
OPERATIONS = ("Put", "Update", "Delete")
_NEW = {"S": "write-landed"}


def _setup_item(ddb, table, pk, stored):
    item = {"pk": {"S": pk}}
    if stored is not None:
        item["attr"] = stored
    ddb.put_item(TableName=table, Item=item)


def _apply(ddb, table, op, pk, condition):
    expected = {"attr": condition}
    try:
        if op == "Put":
            ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "attr": _NEW, "marker": {"S": "applied"}},
                        Expected=expected)
        elif op == "Delete":
            ddb.delete_item(TableName=table, Key={"pk": {"S": pk}}, Expected=expected)
        else:
            ddb.update_item(TableName=table, Key={"pk": {"S": pk}},
                            AttributeUpdates={"marker": {"Value": {"S": "applied"}, "Action": "PUT"}},
                            Expected=expected)
    except ClientError as exc:
        err = exc.response["Error"]
        return "error", err["Code"], err["Message"]
    return "ok", None, None


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Legacy Expected CONTAINS, NOT_CONTAINS, IN, a failing BEGINS_WITH, NULL and NOT_NULL let a
    write land when true and give ConditionalCheckFailedException unchanged when false, including
    CONTAINS matching a set element and IN never matching a scalar against a set attribute.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.Expected.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(TableName=table, KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                      AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                      BillingMode="PAY_PER_REQUEST", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 60})

    for case_name, stored, condition, expect_pass in CASES:
        for op in OPERATIONS:
            pk = f"{case_name}-{op}"
            _setup_item(ddb, table, pk, stored)
            kind, code, message = _apply(ddb, table, op, pk, condition)
            label = f"{case_name}/{op}"
            got = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")

            if expect_pass:
                assert kind == "ok", f"{label}: expected the write to land, got {code}: {message!r}"
                if op == "Delete":
                    assert got is None, f"{label}: a passing conditional DeleteItem left an item: {got!r}"
                elif op == "Put":
                    assert got == {"pk": {"S": pk}, "attr": _NEW, "marker": {"S": "applied"}}, (
                        f"{label}: a passing conditional PutItem did not land: {got!r}")
                else:
                    expected_item = {"pk": {"S": pk}, "marker": {"S": "applied"}}
                    if stored is not None:
                        expected_item["attr"] = stored
                    assert got == expected_item, (
                        f"{label}: a passing conditional UpdateItem did not land: {got!r}")
            else:
                assert kind == "error", f"{label}: expected {_ERR_CCFE}, call succeeded"
                assert code == _ERR_CCFE, f"{label}: expected {_ERR_CCFE!r}, got {code!r}"
                assert message == _ERR_CCFE_MESSAGE, (
                    f"{label}: expected AWS exact CCFE message, got {message!r}")
                expected_item = {"pk": {"S": pk}}
                if stored is not None:
                    expected_item["attr"] = stored
                assert got == expected_item, (
                    f"{label}: a rejected {op}Item must leave the item unchanged, got {got!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
