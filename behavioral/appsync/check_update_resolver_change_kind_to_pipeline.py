"""update-resolver-change-kind-to-pipeline."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-resolver-change-kind-to-pipeline"
GROUP = 'resolver'
SERVICES = ['appsync']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResolver can promote a UNIT resolver to PIPELINE kind with a pipelineConfig."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)["apiId"]
    ds_name = ctx.unique_name("sim2real_behav_ds_").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")

    appsync.start_schema_creation(apiId=api_id, definition=b"type Query { ping: String }")
    _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=60,
        interval_s=2,
    )

    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="ping",
        dataSourceName=ds_name,
        kind="UNIT",
        requestMappingTemplate='{"version": "2017-02-28"}',
        responseMappingTemplate='"pong"',
    )

    fn = appsync.create_function(
        apiId=api_id,
        name=ctx.unique_name("sim2real_behav_fn_").replace("-", "_"),
        dataSourceName=ds_name,
        requestMappingTemplate='{"version": "2017-02-28"}',
        responseMappingTemplate='$util.toJson($ctx.result)',
        functionVersion="2018-05-29",
    )["functionConfiguration"]

    updated = appsync.update_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="ping",
        kind="PIPELINE",
        pipelineConfig={"functions": [fn["functionId"]]},
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )["resolver"]
    assert updated["kind"] == "PIPELINE", f"expected kind=PIPELINE, got {updated['kind']!r}"
    assert updated["pipelineConfig"]["functions"] == [fn["functionId"]], (
        f"expected pipelineConfig.functions=[{fn['functionId']!r}], "
        f"got {updated['pipelineConfig'].get('functions')!r}"
    )
    assert "dataSourceName" not in updated, (
        f"expected the UNIT resolver's dataSourceName to be cleared on promotion to PIPELINE, "
        f"but update_resolver still returned dataSourceName={updated.get('dataSourceName')!r}"
    )

    got = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="ping")["resolver"]
    assert got["kind"] == "PIPELINE", f"expected kind=PIPELINE on independent read, got {got['kind']!r}"
    assert got["pipelineConfig"]["functions"] == [fn["functionId"]], (
        f"expected pipelineConfig.functions=[{fn['functionId']!r}] on independent read, "
        f"got {got['pipelineConfig'].get('functions')!r}"
    )
    assert "dataSourceName" not in got, (
        f"expected no dataSourceName on independent read of the promoted resolver, "
        f"got dataSourceName={got.get('dataSourceName')!r}"
    )


def _create_graphql_api(ctx) -> dict:
    """An API_KEY-auth GraphQL API. Sub-resources (data sources, functions,
    resolvers, types) are removed with their owning apiId, so only the API
    itself needs a teardown."""
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": "behavioral"},
    )
    api = resp["graphqlApi"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api["apiId"]))
    return api


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
