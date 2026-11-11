"""op-contract-create-data-source."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-create-data-source"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataSource persists a NONE data source and rejects a declared type missing its config."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)
    ds_name = ctx.unique_name("sim2realds").replace("-", "")[:32]

    created = appsync.create_data_source(
        apiId=api_id,
        name=ds_name,
        type="NONE",
        description="local resolver source",
    )["dataSource"]
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))

    assert created["name"] == ds_name, f"expected name {ds_name!r}, got {created['name']!r}"
    assert created["type"] == "NONE", f"expected type NONE, got {created['type']!r}"
    assert created["description"] == "local resolver source", (
        f"expected description 'local resolver source', got {created['description']!r}"
    )
    assert created["dataSourceArn"].endswith(f"datasources/{ds_name}"), (
        f"expected dataSourceArn ending in 'datasources/{ds_name}', got {created['dataSourceArn']!r}"
    )

    fetched = appsync.get_data_source(apiId=api_id, name=ds_name)["dataSource"]
    assert fetched["type"] == "NONE", f"expected GetDataSource type NONE, got {fetched['type']!r}"

    listed = appsync.list_data_sources(apiId=api_id)["dataSources"]
    assert any(d["name"] == ds_name for d in listed), (
        f"expected {ds_name!r} in ListDataSources, got names {[d['name'] for d in listed]}"
    )

    # Error boundary: declaring type=AWS_LAMBDA without lambdaConfig is malformed.
    bad_name = ctx.unique_name("sim2realbad").replace("-", "")[:32]
    code, message = _error(
        lambda: appsync.create_data_source(apiId=api_id, name=bad_name, type="AWS_LAMBDA")
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Missing Lambda data source config", message

    # The rejected create must not have registered a data source under that name.
    listed_after = appsync.list_data_sources(apiId=api_id)["dataSources"]
    assert not any(d["name"] == bad_name for d in listed_after), (
        f"rejected create must not register {bad_name!r}, but it appears in "
        f"ListDataSources: {[d['name'] for d in listed_after]}"
    )


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
