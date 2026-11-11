"""put-item-vector-hash-search-schema-missing-vs-empty-string."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-vector-hash-search-schema-missing-vs-empty-string"
GROUP = "vector"
SERVICES = ["dynamodb"]

_DIMENSIONS = 4
_EMPTY_HASH_KEY = (
    "ValidationException",
    "One or more parameter values are not valid. A value specified for a secondary index key "
    "is not supported. The AttributeValue for a key attribute cannot contain an empty string "
    "value. IndexName: idx, IndexKey: tenant",
)


def _vec(values):
    return [{"N": repr(float(v))} for v in values]


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


def _budget_s(ctx, cap_s):
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "plane:data", "dp:api")
def run(ctx) -> None:
    """A PutItem omitting a vector index's HASH SearchSchema attribute is accepted but never
    returned by a SearchVectors scoped to any hash value; the same attribute set to an empty
    string is a ValidationException naming the index and the key, and leaves no item behind.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbvechash-")

    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "tenant", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        VectorIndexes=[{
            "IndexName": "idx",
            "VectorAttribute": {"AttributeName": "emb"},
            "Dimensions": _DIMENSIONS,
            "DistanceFunction": "EUCLIDEAN",
            "Projection": {"ProjectionType": "ALL"},
            "SearchSchema": [{"AttributeName": "tenant", "SearchSchemaElementType": "HASH"}],
        }],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    deadline = time.monotonic() + _budget_s(ctx, 240.0)
    tbl = ddb.describe_table(TableName=table)["Table"]
    while not (tbl["TableStatus"] == "ACTIVE" and tbl.get("VectorIndexes")
               and tbl["VectorIndexes"][0].get("IndexStatus") == "ACTIVE"):
        assert time.monotonic() < deadline, f"table/vector index never became ACTIVE: {tbl!r}"
        time.sleep(2)
        tbl = ddb.describe_table(TableName=table)["Table"]

    # Accepted: an item with no value at all for the HASH search-schema attribute.
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "no-tenant"}, "emb": {"L": _vec([0.0, 0.0, 0.0, 0.0])},
    })
    written = ddb.get_item(TableName=table, Key={"pk": {"S": "no-tenant"}}, ConsistentRead=True)
    assert "Item" in written, "the accepted write with no hash attribute left no item behind"
    assert "tenant" not in written["Item"], (
        f"the item unexpectedly carries a tenant attribute: {written['Item']!r}"
    )

    # Two tenants, each with a vector at the query's own position, to search each hash value.
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "tenant-a"}, "tenant": {"S": "a"}, "emb": {"L": _vec([0.0, 0.0, 0.0, 0.0])},
    })
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "tenant-b"}, "tenant": {"S": "b"}, "emb": {"L": _vec([0.0, 0.0, 0.0, 0.0])},
    })

    def _search(tenant):
        search_deadline = time.monotonic() + _budget_s(ctx, 90.0)
        while True:
            results = ddb.search_vectors(
                TableName=table, IndexName="idx", TopK=10,
                SearchVector=_vec([0.0, 0.0, 0.0, 0.0]),
                SearchConditionExpression="tenant = :t",
                ExpressionAttributeValues={":t": {"S": tenant}},
            )["SearchResults"]
            pks = [r["Item"]["pk"]["S"] for r in results]
            if f"tenant-{tenant}" in pks:
                return pks
            assert time.monotonic() < search_deadline, (
                f"the tenant-{tenant} vector never became searchable under tenant={tenant!r}"
            )
            time.sleep(2)

    for_a = _search("a")
    assert for_a == ["tenant-a"], f"search scoped to tenant=a returned {for_a!r}"
    assert "no-tenant" not in for_a, "an item with no hash attribute matched a scoped search"

    for_b = _search("b")
    assert for_b == ["tenant-b"], f"search scoped to tenant=b returned {for_b!r}"
    assert "no-tenant" not in for_b, "an item with no hash attribute matched a scoped search"

    # Rejected: the same attribute, present as an empty string, naming the index and the key.
    expect_error(lambda: ddb.put_item(TableName=table, Item={
        "pk": {"S": "empty-tenant"}, "tenant": {"S": ""}, "emb": {"L": _vec([0.0, 0.0, 0.0, 0.0])},
    }), *_EMPTY_HASH_KEY)
    absent = ddb.get_item(TableName=table, Key={"pk": {"S": "empty-tenant"}}, ConsistentRead=True)
    assert "Item" not in absent, f"the rejected write left an item behind: {absent.get('Item')!r}"

    # Unchanged state: tenant a still answers exactly as before the refusal.
    again_a = _search("a")
    assert again_a == ["tenant-a"], f"search scoped to tenant=a after the refusal returned {again_a!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
