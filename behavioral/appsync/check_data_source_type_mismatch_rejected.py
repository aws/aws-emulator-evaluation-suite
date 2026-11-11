"""data-source-type-mismatch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-source-type-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataSource with type=AMAZON_DYNAMODB and no dynamodbConfig fails BadRequestException and
    creates nothing; type=HTTP with an httpConfig succeeds and GetDataSource shows the exact endpoint."""
    appsync = ctx.client("appsync")
    api_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-api-"), authenticationType="API_KEY"
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    bad_name = ctx.unique_name("ddsBad").replace("-", "")[:32]
    error = _error(
        lambda: appsync.create_data_source(apiId=api_id, name=bad_name, type="AMAZON_DYNAMODB")
    )
    expected = ("BadRequestException", "Missing DynamoDB data source config")
    assert error == expected, f"expected {expected}, got {error}"

    not_found = _error(lambda: appsync.get_data_source(apiId=api_id, name=bad_name))
    expected = ("NotFoundException", f"Data source {bad_name} not found")
    assert not_found == expected, (
        f"rejected create should leave no data source behind ({expected}), GetDataSource gave {not_found}"
    )

    good_name = ctx.unique_name("httpDs").replace("-", "")[:32]
    good = appsync.create_data_source(
        apiId=api_id,
        name=good_name,
        type="HTTP",
        httpConfig={"endpoint": "https://example.com"},
    )["dataSource"]
    assert good["httpConfig"]["endpoint"] == "https://example.com", good

    fetched = appsync.get_data_source(apiId=api_id, name=good_name)["dataSource"]
    assert fetched["type"] == "HTTP", f"expected type HTTP, got {fetched['type']}"
    assert fetched["httpConfig"]["endpoint"] == "https://example.com", (
        f"expected endpoint https://example.com, got {fetched.get('httpConfig')}"
    )


def _error(fn):
    """Call fn(); return its (error code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
