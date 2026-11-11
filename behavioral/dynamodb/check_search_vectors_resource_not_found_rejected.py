"""search-vectors-resource-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-vectors-resource-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchVectors with a nonexistent index on an existing table returns ValidationException
    naming the index, and the table's vector index list never gains that name."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-novecidx-")
    bogus_index = "nonexistent-vector-index"
    search_vector = [{"N": str(i / 10.0)} for i in range(8)]

    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    def _search():
        ddb.search_vectors(
            TableName=table_name,
            IndexName=bogus_index,
            SearchVector=search_vector,
            TopK=5,
        )

    code, message = _error_info(_search)
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message}"
    expected = f"The table does not have the specified index: {bogus_index}"
    assert message == expected, f"expected the message naming the bogus index, got: {message!r}"

    described = ddb.describe_table(TableName=table_name)["Table"]
    assert described["TableStatus"] == "ACTIVE", f"table went missing/inactive: {described}"
    existing_index_names = [vi["IndexName"] for vi in described.get("VectorIndexes", [])]
    assert bogus_index not in existing_index_names, (
        f"{bogus_index} should never have been created on {table_name}, "
        f"got indexes {existing_index_names}"
    )


def _error_info(fn):
    try:
        fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError("expected search_vectors to raise, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
