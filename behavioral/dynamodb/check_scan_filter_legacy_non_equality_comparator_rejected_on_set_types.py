"""scan-filter-legacy-non-equality-comparator-rejected-on-set-types."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filter-legacy-non-equality-comparator-rejected-on-set-types"
GROUP = "scan"
SERVICES = ["dynamodb"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Legacy ScanFilter BEGINS_WITH on SS, IN on NS and BETWEEN on BS are each
    ValidationException naming the operator and the set type; EQ on the SS attribute matches.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-setop-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={
        "pk": {"S": "p1"},
        "ssattr": {"SS": ["a", "b"]},
        "nsattr": {"NS": ["1", "2"]},
        "bsattr": {"BS": [b"x", b"y"]},
    })

    cases = (
        ("ssattr", "SS", "BEGINS_WITH", [{"SS": ["a"]}]),
        ("nsattr", "NS", "IN", [{"NS": ["1"]}, {"NS": ["2"]}]),
        ("bsattr", "BS", "BETWEEN", [{"BS": [b"a"]}, {"BS": [b"z"]}]),
    )

    for attr, type_name, op, values in cases:
        code, message = _error(lambda attr=attr, op=op, values=values: ddb.scan(
            TableName=table, ScanFilter={attr: {"ComparisonOperator": op, "AttributeValueList": values}}))
        assert code == "ValidationException", f"{attr}/{op}: expected ValidationException, got {code}: {message!r}"
        want = f"One or more parameter values were invalid: ComparisonOperator {op} is not valid for {type_name} AttributeValue type"
        assert message == want, f"{attr}/{op}: expected {want!r}, got {message!r}"

    # Positive control: EQ, the operator the set types do accept, still matches each attribute.
    resp = ddb.scan(TableName=table, ConsistentRead=True, ScanFilter={
        "ssattr": {"ComparisonOperator": "EQ", "AttributeValueList": [{"SS": ["b", "a"]}]},
    })
    assert resp["Count"] == 1, f"positive control: EQ on ssattr expected 1 match, got Count={resp['Count']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
