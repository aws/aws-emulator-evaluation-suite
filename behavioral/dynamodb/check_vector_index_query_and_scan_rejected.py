"""vector-index-query-and-scan-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vector-index-query-and-scan-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query and Scan naming a vector index are rejected with ValidationException;
    SearchVectors on the same index still succeeds.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-ddbvecqs-")
    index = "vec-idx"

    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        VectorIndexes=[{
            "IndexName": index,
            "Dimensions": 2,
            "DistanceFunction": "COSINE",
            "Projection": {"ProjectionType": "ALL"},
            "VectorAttribute": {"AttributeName": "Embedding"},
        }],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    described = _poll_until(
        lambda: ddb.describe_table(TableName=table)["Table"],
        lambda t: t["TableStatus"] == "ACTIVE"
        and t.get("VectorIndexes")
        and t["VectorIndexes"][0]["IndexStatus"] == "ACTIVE",
        timeout_s=300, interval_s=5,
    )
    assert described["VectorIndexes"][0]["IndexName"] == index, (
        f"described vector index name {described['VectorIndexes'][0]['IndexName']!r}, expected {index!r}"
    )

    ddb.put_item(TableName=table, Item={
        "pk": {"S": "item-a"}, "Embedding": {"L": [{"N": "1.0"}, {"N": "0.0"}]}})
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "item-b"}, "Embedding": {"L": [{"N": "0.0"}, {"N": "1.0"}]}})

    _QUERY_REJECTED = (
        "ValidationException",
        "Query operation not supported on this index type.",
    )
    query_got = _error(lambda: ddb.query(
        TableName=table, IndexName=index,
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": {"S": "item-a"}}))
    assert query_got == _QUERY_REJECTED, (
        f"Query naming the vector index raised {query_got!r}, expected {_QUERY_REJECTED!r}"
    )

    _SCAN_REJECTED = (
        "ValidationException",
        "Scan operation not supported on this index type.",
    )
    scan_got = _error(lambda: ddb.scan(TableName=table, IndexName=index))
    assert scan_got == _SCAN_REJECTED, (
        f"Scan naming the vector index raised {scan_got!r}, expected {_SCAN_REJECTED!r}"
    )

    # Positive control: SearchVectors on the very same index succeeds, so the rejections
    # above are about the operation naming a vector index, not about the index itself.
    results = _poll_until(
        lambda: ddb.search_vectors(
            TableName=table, IndexName=index,
            SearchVector=[{"N": "1.0"}, {"N": "0.0"}], TopK=2,
        )["SearchResults"],
        lambda r: len(r) == 2,
        timeout_s=180, interval_s=5,
    )
    pks = sorted(r["Item"]["pk"]["S"] for r in results)
    assert pks == ["item-a", "item-b"], (
        f"SearchVectors on the same index returned pks {pks!r}, expected ['item-a', 'item-b']"
    )

    # Positive control: Query and Scan against the base table (naming no index) still work.
    base_query = ddb.query(TableName=table, KeyConditionExpression="pk = :pk",
                            ExpressionAttributeValues={":pk": {"S": "item-a"}}, ConsistentRead=True)
    assert base_query["Count"] == 1, (
        f"a base-table Query for item-a returned Count {base_query['Count']!r}, expected 1"
    )
    base_scan = ddb.scan(TableName=table, Select="COUNT", ConsistentRead=True)
    assert base_scan["Count"] == 2, (
        f"a base-table Scan returned Count {base_scan['Count']!r}, expected 2"
    )


def _error(fn) -> tuple:
    """The AWS (code, message) fn() raises. RAISES when the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
