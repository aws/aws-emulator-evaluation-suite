"""scan-filter-binary-attribute-unsigned-byte-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-binary-attribute-unsigned-byte-order"
GROUP = 'scan'
SERVICES = ['dynamodb']

#: Four one-byte values spanning the signed/unsigned boundary, plus a value that is a byte-for-byte
#: prefix of another. Every expected set below is derived from these at run time.
_ITEMS = (
    ("v01", b"\x01"),
    ("v7f", b"\x7f"),
    ("v80", b"\x80"),
    ("v80ext", b"\x80\x00"),
    ("vff", b"\xff"),
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """ScanFilter and FilterExpression compare a Binary attribute as unsigned bytes for EQ, GT,
    BEGINS_WITH and CONTAINS -- 0x80 and 0xff sort above 0x01 and 0x7f, not below.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-scanbin-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 30})

    for item_id, value in _ITEMS:
        ddb.put_item(TableName=table, Item={"id": {"S": item_id}, "bin": {"B": value}})

    def scan_ids(**kwargs) -> list:
        resp = ddb.scan(TableName=table, ConsistentRead=True, **kwargs)
        return sorted(item["id"]["S"] for item in resp["Items"])

    greater_than_7f = {"v80", "v80ext", "vff"}

    gt = scan_ids(ScanFilter={"bin": {"ComparisonOperator": "GT",
                                      "AttributeValueList": [{"B": b"\x7f"}]}})
    assert set(gt) == greater_than_7f, (
        f"ScanFilter GT 0x7f returned {gt!r}; unsigned order puts 0x80, 0x80-0x00 and 0xff "
        f"above 0x7f, not below"
    )

    gt_expr = scan_ids(FilterExpression="bin > :v", ExpressionAttributeValues={":v": {"B": b"\x7f"}})
    assert set(gt_expr) == greater_than_7f, (
        f"FilterExpression 'bin > :v' returned {gt_expr!r}, must match legacy GT's {gt!r}"
    )

    eq = scan_ids(ScanFilter={"bin": {"ComparisonOperator": "EQ",
                                      "AttributeValueList": [{"B": b"\x80"}]}})
    assert eq == ["v80"], f"ScanFilter EQ 0x80 returned {eq!r}, expected only the exact match"

    begins_with = scan_ids(ScanFilter={"bin": {"ComparisonOperator": "BEGINS_WITH",
                                               "AttributeValueList": [{"B": b"\x80"}]}})
    assert set(begins_with) == {"v80", "v80ext"}, (
        f"ScanFilter BEGINS_WITH 0x80 returned {begins_with!r}, expected the exact byte and its "
        f"extension, not the unrelated values"
    )

    contains = scan_ids(ScanFilter={"bin": {"ComparisonOperator": "CONTAINS",
                                            "AttributeValueList": [{"B": b"\x00"}]}})
    assert contains == ["v80ext"], (
        f"ScanFilter CONTAINS 0x00 returned {contains!r}, expected only the value holding it as "
        f"a subsequence"
    )

    contains_expr = scan_ids(FilterExpression="contains(bin, :v)",
                             ExpressionAttributeValues={":v": {"B": b"\x00"}})
    assert contains_expr == contains, (
        f"FilterExpression 'contains(bin, :v)' returned {contains_expr!r}, must match legacy "
        f"CONTAINS's {contains!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
