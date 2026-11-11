"""op-contract-updateDataSource-missing-lambda-config-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-updateDataSource-missing-lambda-config-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDataSource retypes a NONE data source to HTTP, visible via GetDataSource.
    Retyping to AWS_LAMBDA without lambdaConfig is rejected with BadRequestException and the
    data source keeps its prior HTTP config."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx, appsync)

    ds_name = ctx.unique_name("sim2real-ds-").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))

    updated = appsync.update_data_source(
        apiId=api_id,
        name=ds_name,
        type="HTTP",
        httpConfig={"endpoint": "https://example.com"},
    )
    assert updated["dataSource"]["type"] == "HTTP", f"expected HTTP after retype, got {updated['dataSource']}"
    assert updated["dataSource"]["httpConfig"]["endpoint"] == "https://example.com", (
        f"expected the given endpoint to be reflected, got {updated['dataSource'].get('httpConfig')}"
    )

    fetched = appsync.get_data_source(apiId=api_id, name=ds_name)["dataSource"]
    assert fetched["type"] == "HTTP", f"independent read expected type HTTP, got {fetched}"
    assert fetched["httpConfig"]["endpoint"] == "https://example.com", (
        f"independent read expected the retyped httpConfig, got {fetched.get('httpConfig')}"
    )

    code, message = _error(lambda: appsync.update_data_source(apiId=api_id, name=ds_name, type="AWS_LAMBDA"))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Missing Lambda data source config", f"unexpected BadRequestException message {message!r}"

    unchanged = appsync.get_data_source(apiId=api_id, name=ds_name)["dataSource"]
    assert unchanged["type"] == "HTTP", "rejected UpdateDataSource must not have retyped the data source"
    assert unchanged["httpConfig"]["endpoint"] == "https://example.com", (
        f"rejected UpdateDataSource must not have touched httpConfig, got {unchanged.get('httpConfig')}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected BadRequestException, but the call SUCCEEDED and returned {result!r}")


def _create_graphql_api(ctx, appsync):
    name = ctx.unique_name("sim2real-appsync-")
    resp = appsync.create_graphql_api(name=name, authenticationType="API_KEY")
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
