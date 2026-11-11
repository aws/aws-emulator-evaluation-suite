"""scan-filter-expression-le-ge-and-binary-begins-with."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-expression-le-ge-and-binary-begins-with"
GROUP = "scan"
SERVICES = ["dynamodb"]

#: Five seeded items: a string name, a number score and a binary blob. Every expected set below
#: is derived from these at run time.
_ROWS = (
    ("id1", "apple", "10", b"\x01\xaa"),
    ("id2", "banana", "20", b"\x01\xbb"),
    ("id3", "cherry", "30", b"\x02\xaa"),
    ("id4", "date", "40", b"\x02\xbb"),
    ("id5", "eggplant", "50", b"\x03\xaa"),
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression's <= on an S and an N attribute, >= on an N attribute, and
    begins_with() on a B attribute each match the legacy ScanFilter twin's set exactly.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-scanle-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for item_id, name, score, blob in _ROWS:
        ddb.put_item(TableName=table, Item={
            "id": {"S": item_id}, "name": {"S": name}, "score": {"N": score}, "blob": {"B": blob},
        })

    def scan_ids(**kwargs) -> set:
        ids, start = set(), None
        while True:
            extra = {"ExclusiveStartKey": start} if start else {}
            page = ddb.scan(TableName=table, ConsistentRead=True, **kwargs, **extra)
            ids.update(item["id"]["S"] for item in page["Items"])
            start = page.get("LastEvaluatedKey")
            if not start:
                return ids

    # <= on an S attribute: name <= 'cherry' selects every name at or before it in byte order.
    name_le = {r[0] for r in _ROWS if r[1].encode("utf-8") <= b"cherry"}
    fe_name_le = scan_ids(FilterExpression="#n <= :v", ExpressionAttributeNames={"#n": "name"},
                          ExpressionAttributeValues={":v": {"S": "cherry"}})
    assert fe_name_le == name_le, (
        f"FilterExpression 'name <= cherry' returned {fe_name_le!r}, expected {name_le!r}"
    )
    legacy_name_le = scan_ids(ScanFilter={"name": {"ComparisonOperator": "LE",
                                                    "AttributeValueList": [{"S": "cherry"}]}})
    assert legacy_name_le == fe_name_le, (
        f"legacy ScanFilter LE on name returned {legacy_name_le!r}, must match FilterExpression's "
        f"{fe_name_le!r}"
    )

    # <= on an N attribute: score <= 30 selects the three lowest scores, compared numerically.
    score_le = {r[0] for r in _ROWS if int(r[2]) <= 30}
    fe_score_le = scan_ids(FilterExpression="score <= :v", ExpressionAttributeValues={":v": {"N": "30"}})
    assert fe_score_le == score_le, (
        f"FilterExpression 'score <= 30' returned {fe_score_le!r}, expected {score_le!r}"
    )
    legacy_score_le = scan_ids(ScanFilter={"score": {"ComparisonOperator": "LE",
                                                      "AttributeValueList": [{"N": "30"}]}})
    assert legacy_score_le == fe_score_le, (
        f"legacy ScanFilter LE on score returned {legacy_score_le!r}, must match FilterExpression's "
        f"{fe_score_le!r}"
    )

    # >= on an N attribute: score >= 30 selects the three highest scores.
    score_ge = {r[0] for r in _ROWS if int(r[2]) >= 30}
    fe_score_ge = scan_ids(FilterExpression="score >= :v", ExpressionAttributeValues={":v": {"N": "30"}})
    assert fe_score_ge == score_ge, (
        f"FilterExpression 'score >= 30' returned {fe_score_ge!r}, expected {score_ge!r}"
    )
    legacy_score_ge = scan_ids(ScanFilter={"score": {"ComparisonOperator": "GE",
                                                      "AttributeValueList": [{"N": "30"}]}})
    assert legacy_score_ge == fe_score_ge, (
        f"legacy ScanFilter GE on score returned {legacy_score_ge!r}, must match FilterExpression's "
        f"{fe_score_ge!r}"
    )

    # begins_with() on a B attribute: blob starting with the single byte 0x01.
    blob_bw = {r[0] for r in _ROWS if r[3].startswith(b"\x01")}
    fe_blob_bw = scan_ids(FilterExpression="begins_with(#b, :v)",
                         ExpressionAttributeNames={"#b": "blob"},
                         ExpressionAttributeValues={":v": {"B": b"\x01"}})
    assert fe_blob_bw == blob_bw, (
        f"FilterExpression 'begins_with(blob, 0x01)' returned {fe_blob_bw!r}, expected {blob_bw!r}"
    )
    legacy_blob_bw = scan_ids(ScanFilter={"blob": {"ComparisonOperator": "BEGINS_WITH",
                                                    "AttributeValueList": [{"B": b"\x01"}]}})
    assert legacy_blob_bw == fe_blob_bw, (
        f"legacy ScanFilter BEGINS_WITH on blob returned {legacy_blob_bw!r}, must match "
        f"FilterExpression's {fe_blob_bw!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
