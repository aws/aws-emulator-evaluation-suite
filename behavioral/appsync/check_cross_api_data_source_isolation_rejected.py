"""cross-api-data-source-isolation-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cross-api-data-source-isolation-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A data source created under one API must not be visible/gettable under a different, unrelated API."""
    appsync = ctx.client("appsync")
    api1 = _create_graphql_api(ctx)
    api2 = _create_graphql_api(ctx)

    ds_name = ctx.unique_name("sim2real_behav_ds_").replace("-", "_")
    appsync.create_data_source(apiId=api1["apiId"], name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api1["apiId"], name=ds_name))

    # sanity: visible under its own API
    own = appsync.get_data_source(apiId=api1["apiId"], name=ds_name)["dataSource"]
    assert own["name"] == ds_name, f"expected {ds_name!r} visible under its own API, got {own!r}"

    # cross-tenant isolation: same name under a *different* API must be reported NotFound
    error = _error(lambda: appsync.get_data_source(apiId=api2["apiId"], name=ds_name))
    expected = ("NotFoundException", f"Data source {ds_name} not found")
    assert error == expected, f"expected {expected}, got {error}"

    # and must not appear in that other API's listing either
    other_listing = appsync.list_data_sources(apiId=api2["apiId"])["dataSources"]
    assert all(d["name"] != ds_name for d in other_listing), other_listing


def _create_graphql_api(ctx) -> dict:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(
        name=name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = resp["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return {"apiId": api_id, "name": name, "arn": resp["arn"]}


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
