"""create-data-source-type-config-mismatch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-data-source-type-config-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDataSource with type=AMAZON_DYNAMODB and no dynamodbConfig is rejected (type and config
    are cross-validated), while a type=NONE data source on the same API is accepted."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx)
    api_id = api["apiId"]
    ds_name = ctx.unique_name("sim2real_ds_").replace("-", "_")

    code, message = _error(
        lambda: appsync.create_data_source(apiId=api_id, name=ds_name, type="AMAZON_DYNAMODB")
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Missing DynamoDB data source config", f"expected the exact refusal message, got {message!r}"

    listed = appsync.list_data_sources(apiId=api_id)["dataSources"]
    assert listed == [], f"a mismatched data source should never have been created: {listed}"

    good_name = ctx.unique_name("sim2real_ds_ok_").replace("-", "_")
    good = appsync.create_data_source(apiId=api_id, name=good_name, type="NONE")["dataSource"]
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=good_name))
    assert good["type"] == "NONE", f"positive control should have succeeded: {good}"

    fetched = appsync.get_data_source(apiId=api_id, name=good_name)["dataSource"]
    assert fetched["name"] == good_name and fetched["type"] == "NONE", (
        f"expected name={good_name!r} type=NONE, got {fetched}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_graphql_api(ctx, auth_type="API_KEY"):
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType=auth_type,
        tags={"sim2real": "true"},
    )
    api = resp["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
