"""legacy-expected-scalar-comparator-matrix-put-item."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "legacy-expected-scalar-comparator-matrix-put-item"
GROUP = "conditions"
SERVICES = ["dynamodb"]
_ERR_CCFE = "ConditionalCheckFailedException"
_ERR_CCFE_MESSAGE = "The conditional request failed"
_NEW = {"S": "put-landed"}

# (case_name, stored attr value, Expected clause for 'attr', expect the write to land)
CASES = [
    ("ne_true", {"N": "5"}, {"ComparisonOperator": "NE", "AttributeValueList": [{"N": "6"}]}, True),
    ("ne_false", {"N": "5"}, {"ComparisonOperator": "NE", "AttributeValueList": [{"N": "5"}]}, False),
    ("lt_true_bytes", {"S": "B"}, {"ComparisonOperator": "LT", "AttributeValueList": [{"S": "a"}]}, True),
    ("lt_false_bytes", {"S": "a"}, {"ComparisonOperator": "LT", "AttributeValueList": [{"S": "B"}]}, False),
    ("le_true_equal", {"N": "5"}, {"ComparisonOperator": "LE", "AttributeValueList": [{"N": "5"}]}, True),
    ("le_false", {"N": "6"}, {"ComparisonOperator": "LE", "AttributeValueList": [{"N": "5"}]}, False),
    ("gt_true_numeric", {"N": "10"}, {"ComparisonOperator": "GT", "AttributeValueList": [{"N": "9"}]}, True),
    ("gt_false_numeric", {"N": "9"}, {"ComparisonOperator": "GT", "AttributeValueList": [{"N": "10"}]}, False),
    ("ge_true_equal", {"N": "5"}, {"ComparisonOperator": "GE", "AttributeValueList": [{"N": "5"}]}, True),
    ("ge_false", {"N": "4"}, {"ComparisonOperator": "GE", "AttributeValueList": [{"N": "5"}]}, False),
    ("between_true", {"N": "5"}, {"ComparisonOperator": "BETWEEN", "AttributeValueList": [{"N": "1"}, {"N": "10"}]}, True),
    ("between_false", {"N": "11"}, {"ComparisonOperator": "BETWEEN", "AttributeValueList": [{"N": "1"}, {"N": "10"}]}, False),
    ("eq_value_comparator_true", {"S": "match"}, {"Value": {"S": "match"}, "ComparisonOperator": "EQ"}, True),
    ("eq_value_comparator_false", {"S": "mismatch"}, {"Value": {"S": "match"}, "ComparisonOperator": "EQ"}, False),
    ("eq_bool_true", {"BOOL": True}, {"ComparisonOperator": "EQ", "AttributeValueList": [{"BOOL": True}]}, True),
    ("eq_bool_false", {"BOOL": False}, {"ComparisonOperator": "EQ", "AttributeValueList": [{"BOOL": True}]}, False),
]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Every legacy Expected scalar comparator (NE, LT, LE, GT, GE, BETWEEN, EQ via Value and
    ComparisonOperator, EQ on BOOL) lets PutItem land when true, comparing N numerically and S
    by UTF-8 byte order, and gives ConditionalCheckFailedException unchanged when false.

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
        pk = case_name
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "attr": stored})

        try:
            ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "attr": _NEW, "marker": {"S": "applied"}},
                         Expected={"attr": condition})
            succeeded = True
            error_code = None
        except ClientError as exc:
            succeeded = False
            error_code = exc.response["Error"]["Code"]
            error_message = exc.response["Error"]["Message"]

        got = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")
        if expect_pass:
            assert succeeded, f"{case_name}: expected the write to land, got {error_code!r}"
            assert got == {"pk": {"S": pk}, "attr": _NEW, "marker": {"S": "applied"}}, (
                f"{case_name}: a passing conditional PutItem did not land: {got!r}")
        else:
            assert not succeeded, f"{case_name}: expected ConditionalCheckFailedException, call succeeded"
            assert error_code == _ERR_CCFE, f"{case_name}: expected {_ERR_CCFE!r}, got {error_code!r}"
            assert error_message == _ERR_CCFE_MESSAGE, (
                f"{case_name}: expected AWS exact CCFE message, got {error_message!r}")
            assert got == {"pk": {"S": pk}, "attr": stored}, (
                f"{case_name}: a rejected PutItem must leave the item unchanged, got {got!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
