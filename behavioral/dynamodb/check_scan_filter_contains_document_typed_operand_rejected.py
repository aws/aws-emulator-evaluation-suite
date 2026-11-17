"""scan-filter-contains-document-typed-operand-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filter-contains-document-typed-operand-rejected"
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
    """Legacy ScanFilter CONTAINS refuses an M- or L-typed AttributeValueList entry with
    ValidationException naming that document type, while a BOOL or NULL operand is accepted
    and a matching scalar operand still finds its item.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddbdoc-")
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
    ddb.put_item(TableName=t, Item={"pk": {"S": "i2"}, "coll": {"S": "needle"}})

    for doc_type, doc_value in (("M", {"M": {"k": {"S": "a"}}}), ("L", {"L": [{"S": "a"}]})):
        code, message = _error(lambda doc_value=doc_value: ddb.scan(
            TableName=t,
            ScanFilter={"coll": {"ComparisonOperator": "CONTAINS", "AttributeValueList": [doc_value]}},
        ))
        assert code == _VALIDATION, (
            f"CONTAINS with a {doc_type} operand: expected {_VALIDATION}, got {code}: {message!r}"
        )
        want = (
            f"One or more parameter values were invalid: ComparisonOperator CONTAINS is not "
            f"valid for {doc_type} AttributeValue type"
        )
        assert message == want, (
            f"CONTAINS with a {doc_type} operand: expected message {want!r}, got {message!r}"
        )

    for scalar_value in ({"BOOL": True}, {"NULL": True}):
        resp = ddb.scan(
            TableName=t, ConsistentRead=True,
            ScanFilter={"coll": {"ComparisonOperator": "CONTAINS", "AttributeValueList": [scalar_value]}},
        )
        assert resp["Count"] == 0, (
            f"CONTAINS with operand {scalar_value!r} matched {resp['Count']} items, expected 0 "
            f"-- it is accepted, not rejected, but matches nothing on a string-set attribute"
        )

    found = ddb.scan(
        TableName=t, ConsistentRead=True,
        ScanFilter={"coll": {"ComparisonOperator": "CONTAINS", "AttributeValueList": [{"S": "needle"}]}},
    )
    assert {i["pk"]["S"] for i in found["Items"]} == {"i2"}, (
        f"CONTAINS with a matching S operand returned {found['Items']!r}, expected only item i2"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
