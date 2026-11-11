"""op-contract-updateDataSource."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-updateDataSource"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDataSource persists a description change; a type/config mismatch (AWS_LAMBDA w/o lambdaConfig) is rejected and leaves the data source's type and description unchanged."""
    appsync = ctx.client("appsync")
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    ds_name = "sim2realDataSource"
    appsync.create_data_source(
        apiId=api_id, name=ds_name, type="NONE", description="initial"
    )
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))

    appsync.update_data_source(
        apiId=api_id, name=ds_name, type="NONE", description="updated"
    )
    ds = appsync.get_data_source(apiId=api_id, name=ds_name)["dataSource"]
    assert ds["description"] == "updated", f"expected description 'updated', got {ds}"

    code, message = _error(
        lambda: appsync.update_data_source(apiId=api_id, name=ds_name, type="AWS_LAMBDA")
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException for AWS_LAMBDA type missing lambdaConfig, got {code}"
    )
    assert message == "Missing Lambda data source config", f"unexpected BadRequestException message {message!r}"

    unchanged = appsync.get_data_source(apiId=api_id, name=ds_name)["dataSource"]
    assert unchanged["type"] == "NONE", (
        f"rejected UpdateDataSource must not have retyped the data source, got {unchanged}"
    )
    assert unchanged["description"] == "updated", (
        f"rejected UpdateDataSource must not have changed description, got {unchanged}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
