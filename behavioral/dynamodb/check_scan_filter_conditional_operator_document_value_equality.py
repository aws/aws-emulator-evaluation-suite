"""scan-filter-conditional-operator-document-value-equality."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filter-conditional-operator-document-value-equality"
GROUP = 'scan'
SERVICES = ['dynamodb']


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
    """ConditionalOperator AND/OR compose EQ on List and Map ScanFilter conditions by deep
    structural equality; any other ConditionalOperator value is rejected, naming AND as ALL.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-scancond-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 30})

    list_value = {"L": [{"S": "x"}, {"N": "1"}]}
    map_value = {"M": {"a": {"S": "y"}, "b": {"N": "1"}}}
    ddb.put_item(TableName=table, Item={"id": {"S": "list-match"}, "doc": list_value})
    ddb.put_item(TableName=table, Item={"id": {"S": "list-other"}, "doc": {"L": [{"S": "x"}, {"N": "2"}]}})
    ddb.put_item(TableName=table, Item={"id": {"S": "map-match"}, "doc": map_value})
    ddb.put_item(TableName=table, Item={"id": {"S": "map-other"}, "doc": {"M": {"a": {"S": "y"}, "b": {"N": "2"}}}})

    def scan_ids(**kwargs) -> list:
        resp = ddb.scan(TableName=table, ConsistentRead=True, **kwargs)
        return sorted(item["id"]["S"] for item in resp["Items"])

    eq_list = scan_ids(ScanFilter={"doc": {"ComparisonOperator": "EQ", "AttributeValueList": [list_value]}})
    assert eq_list == ["list-match"], (
        f"ScanFilter EQ on an L value returned {eq_list!r}, expected only the structurally "
        f"identical List, excluding the one that differs by a nested element"
    )

    eq_map = scan_ids(ScanFilter={"doc": {"ComparisonOperator": "EQ", "AttributeValueList": [map_value]}})
    assert eq_map == ["map-match"], (
        f"ScanFilter EQ on an M value returned {eq_map!r}, expected only the structurally "
        f"identical Map, excluding the one that differs by a nested value"
    )

    and_narrowed = scan_ids(ConditionalOperator="AND", ScanFilter={
        "doc": {"ComparisonOperator": "EQ", "AttributeValueList": [list_value]},
        "id": {"ComparisonOperator": "EQ", "AttributeValueList": [{"S": "list-other"}]},
    })
    assert and_narrowed == [], (
        f"ConditionalOperator AND of a satisfiable condition and an unsatisfiable one returned "
        f"{and_narrowed!r}, expected the empty intersection"
    )

    and_matched = scan_ids(ConditionalOperator="AND", ScanFilter={
        "doc": {"ComparisonOperator": "EQ", "AttributeValueList": [list_value]},
        "id": {"ComparisonOperator": "EQ", "AttributeValueList": [{"S": "list-match"}]},
    })
    assert and_matched == ["list-match"], (
        f"ConditionalOperator AND of two conditions both satisfied by the same item returned "
        f"{and_matched!r}, expected that item alone"
    )

    or_union = scan_ids(ConditionalOperator="OR", ScanFilter={
        "doc": {"ComparisonOperator": "EQ", "AttributeValueList": [map_value]},
        "id": {"ComparisonOperator": "EQ", "AttributeValueList": [{"S": "list-other"}]},
    })
    assert or_union == ["list-other", "map-match"], (
        f"ConditionalOperator OR of two conditions satisfied by different items returned "
        f"{or_union!r}, expected the union of both"
    )

    code, message = _error(lambda: ddb.scan(TableName=table, ConditionalOperator="XOR", ScanFilter={
        "doc": {"ComparisonOperator": "EQ", "AttributeValueList": [map_value]},
        "id": {"ComparisonOperator": "EQ", "AttributeValueList": [{"S": "list-other"}]},
    }))
    assert code == "ValidationException", f"expected ValidationException for an unknown ConditionalOperator, got {code}: {message!r}"
    assert message == (
        "Failed to satisfy constraint: Member must satisfy enum value set: [ALL, OR]"
    ), f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
