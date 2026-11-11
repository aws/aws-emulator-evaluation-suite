"""execute-statement-vector-index-qualified-select-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-vector-index-qualified-select-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_NO_VECTOR_INDEX_QUERY = (
    "ValidationException",
    "Scan operation not supported on this index type",
)


def expect_error(fn, code, message):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got_code, got_message = err.get("Code"), err.get("Message")
    else:
        raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement rejects a SELECT qualified with a table's vector index; a SELECT on the
    base table returns the vector attribute as an ordinary list of numbers."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqlvec-")
    index_name = "vec-idx"
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        VectorIndexes=[{
            "IndexName": index_name,
            "VectorAttribute": {"AttributeName": "embedding"},
            "Dimensions": 3,
            "DistanceFunction": "COSINE",
            "Projection": {"ProjectionType": "ALL"},
        }],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))

    deadline = time.time() + 300
    status = None
    while time.time() < deadline:
        described = ddb.describe_table(TableName=table)["Table"]
        vector_indexes = described.get("VectorIndexes", [])
        status = vector_indexes[0]["IndexStatus"] if vector_indexes else None
        if described["TableStatus"] == "ACTIVE" and status == "ACTIVE":
            break
        time.sleep(2)
    assert status == "ACTIVE", f"vector index never became ACTIVE: {status!r}"

    ddb.put_item(
        TableName=table,
        Item={"pk": {"S": "p1"}, "embedding": {"L": [{"N": "1"}, {"N": "0"}, {"N": "0"}]}},
    )

    # Positive control: a base-table SELECT returns the vector attribute untouched, as an
    # ordinary list of numbers -- PartiQL has no special handling for it at all.
    base = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\" WHERE pk = 'p1'", ConsistentRead=True,
    )
    assert base["Items"] == [
        {"pk": {"S": "p1"}, "embedding": {"L": [{"N": "1"}, {"N": "0"}, {"N": "0"}]}}
    ], f"base-table SELECT did not return the vector attribute as an ordinary list: {base['Items']!r}"

    # Break exactly one thing: qualify the FROM clause with the vector index itself.
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f"SELECT * FROM \"{table}\".\"{index_name}\""
        ),
        *_NO_VECTOR_INDEX_QUERY,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
