"""update-function-change-datasource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-function-change-datasource"
GROUP = 'function'
SERVICES = ['appsync']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFunction can repoint a function at a different data source; the change is durable."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)["apiId"]
    # AppSync data-source / function names must match [_A-Za-z][_0-9A-Za-z]*, so the
    # hyphens ctx.unique_name emits are folded to underscores.
    ds1 = ctx.unique_name("sim2real_behav_ds1_").replace("-", "_")
    ds2 = ctx.unique_name("sim2real_behav_ds2_").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=ds1, type="NONE")
    appsync.create_data_source(apiId=api_id, name=ds2, type="NONE")

    fn_name = ctx.unique_name("sim2real_behav_fn_").replace("-", "_")
    fn = appsync.create_function(
        apiId=api_id,
        name=fn_name,
        dataSourceName=ds1,
        requestMappingTemplate='{"version": "2017-02-28"}',
        responseMappingTemplate='$util.toJson($ctx.result)',
        functionVersion="2018-05-29",
    )["functionConfiguration"]
    function_id = fn["functionId"]
    assert fn["dataSourceName"] == ds1, f"expected initial dataSourceName {ds1!r}, got {fn['dataSourceName']!r}"

    updated = appsync.update_function(
        apiId=api_id,
        name=fn_name,
        functionId=function_id,
        dataSourceName=ds2,
        requestMappingTemplate='{"version": "2017-02-28"}',
        responseMappingTemplate='$util.toJson($ctx.result)',
        functionVersion="2018-05-29",
    )["functionConfiguration"]
    assert updated["dataSourceName"] == ds2, (
        f"UpdateFunction response expected dataSourceName {ds2!r}, got {updated['dataSourceName']!r}"
    )

    got = appsync.get_function(apiId=api_id, functionId=function_id)["functionConfiguration"]
    assert got["dataSourceName"] == ds2, (
        f"independent GetFunction expected dataSourceName {ds2!r}, got {got['dataSourceName']!r}"
    )


def _create_graphql_api(ctx) -> dict:
    """An API_KEY-auth GraphQL API. Sub-resources (data sources, functions,
    resolvers, types) are removed with their owning apiId, so only the API
    itself needs a teardown."""
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"), authenticationType="API_KEY"
    )
    api = resp["graphqlApi"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api["apiId"]))
    return api


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
