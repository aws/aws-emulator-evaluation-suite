"""pipeline-resolver-functions-limit."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipeline-resolver-functions-limit"
GROUP = "resolver"
SERVICES = ["appsync"]

_LIMIT = 10
_SCHEMA = """schema { query: Query }
type Query { widget: String }
"""


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_schema(svc, api_id, *, timeout_s=60, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = svc.get_schema_creation_status(apiId=api_id)
        if status["status"] in ("SUCCESS", "ACTIVE", "FAILED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"schema creation did not reach a terminal status within {timeout_s}s: {status!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A PIPELINE resolver holds up to the 10-function-per-pipeline ceiling; growing it to 11
    is refused and the resolver keeps its prior 10 functions."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": "behavioral"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    svc.start_schema_creation(apiId=api_id, definition=_SCHEMA)
    status = _poll_schema(svc, api_id)
    assert status["status"] in ("SUCCESS", "ACTIVE"), f"schema creation failed: {status!r}"

    ds_name = ctx.unique_name("sim2real_behav_appsync_ds_").replace("-", "_")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))

    function_ids = []
    for i in range(_LIMIT + 1):
        fn_name = ctx.unique_name(f"sim2real_behav_appsync_fn_{i}_").replace("-", "_")
        fn = svc.create_function(
            apiId=api_id,
            name=fn_name,
            dataSourceName=ds_name,
            requestMappingTemplate="{}",
            responseMappingTemplate="$util.toJson($ctx.result)",
            functionVersion="2018-05-29",
        )["functionConfiguration"]
        function_ids.append(fn["functionId"])
        ctx.on_cleanup(lambda _fid=fn["functionId"]: svc.delete_function(apiId=api_id, functionId=_fid))

    at_limit_ids = function_ids[:_LIMIT]
    resolver = svc.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="widget",
        kind="PIPELINE",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.prev.result)",
        pipelineConfig={"functions": at_limit_ids},
    )["resolver"]
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="widget"))

    got = svc.get_resolver(apiId=api_id, typeName="Query", fieldName="widget")["resolver"]
    assert got["pipelineConfig"]["functions"] == at_limit_ids, (
        f"expected the resolver to hold exactly the {_LIMIT} functions it was created with, "
        f"got {got['pipelineConfig']['functions']!r}"
    )

    over_limit_ids = function_ids[: _LIMIT + 1]
    code, message = _error(
        lambda: svc.update_resolver(
            apiId=api_id,
            typeName="Query",
            fieldName="widget",
            kind="PIPELINE",
            requestMappingTemplate="{}",
            responseMappingTemplate="$util.toJson($ctx.prev.result)",
            pipelineConfig={"functions": over_limit_ids},
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException once the per-pipeline function ceiling of {_LIMIT} is "
        f"exceeded, got {code}: {message!r}"
    )
    assert message == f"A resolver can only be composed of {_LIMIT} functions.", (
        f"expected AWS's exact ceiling message naming the {_LIMIT}-function limit, got {message!r}"
    )

    unchanged = svc.get_resolver(apiId=api_id, typeName="Query", fieldName="widget")["resolver"]
    assert unchanged["pipelineConfig"]["functions"] == at_limit_ids, (
        f"the rejected UpdateResolver must leave the resolver's functions unchanged: expected "
        f"{at_limit_ids!r}, got {unchanged['pipelineConfig']['functions']!r}"
    )

    restored = svc.update_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="widget",
        kind="PIPELINE",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.prev.result)",
        pipelineConfig={"functions": list(reversed(at_limit_ids))},
    )["resolver"]
    assert restored["pipelineConfig"]["functions"] == list(reversed(at_limit_ids)), (
        f"an identical-shape update back at {_LIMIT} functions must succeed, got "
        f"{restored['pipelineConfig']['functions']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
