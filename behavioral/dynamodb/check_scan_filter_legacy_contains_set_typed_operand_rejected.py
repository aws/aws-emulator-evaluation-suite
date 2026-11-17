"""scan-filter-legacy-contains-set-typed-operand-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filter-legacy-contains-set-typed-operand-rejected"
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
    """Legacy ScanFilter CONTAINS and NOT_CONTAINS refuse a Set-typed (SS, NS or BS)
    AttributeValueList entry with ValidationException; a scalar operand still matches.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddbset-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=t, Item={"pk": {"S": "i1"}, "coll": {"SS": ["a", "b"]}})

    for op in ("CONTAINS", "NOT_CONTAINS"):
        for set_value in ({"SS": ["a"]}, {"NS": ["1"]}, {"BS": [b"a"]}):
            set_type = next(iter(set_value))
            code, message = _error(lambda op=op, set_value=set_value: ddb.scan(
                TableName=t,
                ScanFilter={"coll": {"ComparisonOperator": op, "AttributeValueList": [set_value]}},
            ))
            assert code == _VALIDATION, (
                f"{op} with a {set_type} operand: expected {_VALIDATION}, got {code}: {message!r}"
            )
            want = (
                f"One or more parameter values were invalid: ComparisonOperator {op} is not "
                f"valid for {set_type} AttributeValue type"
            )
            assert message == want, (
                f"{op} with a {set_type} operand: expected message {want!r}, got {message!r}"
            )

    # Positive control: the same attribute under a scalar S operand still matches, proving the
    # refusals above are about the operand's type, not a broken table or filter.
    resp = ddb.scan(TableName=t, ConsistentRead=True,
                    ScanFilter={"coll": {"ComparisonOperator": "CONTAINS",
                                         "AttributeValueList": [{"S": "a"}]}})
    ids = sorted(i["pk"]["S"] for i in resp["Items"])
    assert ids == ["i1"], f"CONTAINS with a scalar S operand: expected ['i1'], got {ids!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
