"""data-source-type-config-mismatch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-source-type-config-mismatch-rejected"
GROUP = "data-source"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Creating an AMAZON_DYNAMODB data source without the required dynamodbConfig is
    rejected with BadRequestException, leaves no data source behind, and a properly
    configured sibling create on the same API still succeeds."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    bad_name = _safe_name(ctx, "dsbad")
    error = _error(
        lambda: appsync.create_data_source(apiId=api_id, name=bad_name, type="AMAZON_DYNAMODB")
    )
    expected = ("BadRequestException", "Missing DynamoDB data source config")
    assert error == expected, f"expected {expected}, got {error!r}"

    not_found = _error(lambda: appsync.get_data_source(apiId=api_id, name=bad_name))
    expected = ("NotFoundException", f"Data source {bad_name} not found")
    assert not_found == expected, (
        f"rejected create should leave no data source behind ({expected}), GetDataSource gave {not_found!r}"
    )

    # Positive control: a validly-configured data source on the same API still succeeds.
    good_name = _safe_name(ctx, "dsgood")
    appsync.create_data_source(apiId=api_id, name=good_name, type="NONE")
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=good_name))
    good = appsync.get_data_source(apiId=api_id, name=good_name)["dataSource"]
    assert good["name"] == good_name, f"expected name {good_name!r}, got {good['name']!r}"
    assert good["type"] == "NONE", f"expected type 'NONE', got {good['type']!r}"


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(name=name, authenticationType="API_KEY")
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _safe_name(ctx, kind: str) -> str:
    raw = ctx.unique_name(f"sim2real{kind}")
    return "".join(c if c.isalnum() or c == "_" else "_" for c in raw)


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
