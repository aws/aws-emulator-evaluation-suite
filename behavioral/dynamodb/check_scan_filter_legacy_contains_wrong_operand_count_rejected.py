"""scan-filter-legacy-contains-wrong-operand-count-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filter-legacy-contains-wrong-operand-count-rejected"
GROUP = "scan"
SERVICES = ["dynamodb"]
_VALIDATION = "ValidationException"


def _error(fn):
    """The Error.Code and Error.Message `fn` raises. Raises on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Legacy ScanFilter CONTAINS with zero or two AttributeValueList entries is
    ValidationException with AWS's exact message; CONTAINS with exactly one entry still
    matches the substring.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.ScanFilter.html
    """
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddbcwc-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=name, Item={"id": {"S": "r1"}, "tag": {"S": "banana"}})

    want = ("One or more parameter values were invalid: Invalid number of argument(s) for the "
            "CONTAINS ComparisonOperator")

    code, message = _error(lambda: ddb.scan(
        TableName=name, ScanFilter={"tag": {"AttributeValueList": [], "ComparisonOperator": "CONTAINS"}}))
    assert code == _VALIDATION, f"CONTAINS with 0 values: expected {_VALIDATION}, got {code}"
    assert message == want, f"CONTAINS with 0 values: expected {want!r}, got {message!r}"

    code, message = _error(lambda: ddb.scan(
        TableName=name, ScanFilter={"tag": {"AttributeValueList": [{"S": "an"}, {"S": "na"}],
                                             "ComparisonOperator": "CONTAINS"}}))
    assert code == _VALIDATION, f"CONTAINS with 2 values: expected {_VALIDATION}, got {code}"
    assert message == want, f"CONTAINS with 2 values: expected {want!r}, got {message!r}"

    resp = ddb.scan(TableName=name,
                     ScanFilter={"tag": {"AttributeValueList": [{"S": "an"}], "ComparisonOperator": "CONTAINS"}},
                     ConsistentRead=True)
    ids = sorted(i["id"]["S"] for i in resp["Items"])
    assert ids == ["r1"], f"CONTAINS with exactly 1 value: expected ['r1'], got {ids!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
