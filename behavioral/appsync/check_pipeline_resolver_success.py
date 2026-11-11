"""pipeline-resolver-success."""
from __future__ import annotations

import time
import re

from behavioral_harness import tags
from botocore.exceptions import ClientError

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")

def _sanitize(name):
    """AppSync data source/function names must match ^[_A-Za-z][_0-9A-Za-z]*$."""
    cleaned = re.sub(r"[^0-9A-Za-z_]", "_", name)
    if not cleaned or not re.match(r"[_A-Za-z]", cleaned[0]):
        cleaned = "n_" + cleaned
    return cleaned

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "pipeline-resolver-success"
GROUP = 'resolver'
SERVICES = ['appsync']
DEFAULT_SCHEMA = """schema {
    query: Query
}

type Query {
    getWidget(id: ID!): Widget
    getWidget2(id: ID!): Widget
}

type Widget {
    id: ID!
    name: String
}
"""

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResolver(kind=PIPELINE) referencing a real Function persists pipelineConfig.functions."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(name=ctx.unique_name("sim2real-behav-appsync-api-"), authenticationType="API_KEY")["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    svc.start_schema_creation(apiId=api_id, definition=DEFAULT_SCHEMA)
    _sc = _poll_until(lambda: svc.get_schema_creation_status(apiId=api_id), lambda r: r.get("status") in ("SUCCESS", "ACTIVE", "FAILED"), timeout_s=60, interval_s=1.5, description="schema creation")
    if _sc.get("status") == "FAILED":
        raise AssertionError(f"schema creation failed: {_sc.get('details')}")
    ds = svc.create_data_source(apiId=api_id, name=_sanitize(ctx.unique_name("sim2real-behav-ds_")), type="NONE")["dataSource"]
    ds_name = ds["name"]

    fn = svc.create_function(
        apiId=api_id,
        name=_sanitize(ctx.unique_name("sim2real-behav-fn_")),
        dataSourceName=ds_name,
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
        functionVersion="2018-05-29",
    )["functionConfiguration"]
    function_id = fn["functionId"]

    svc.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getWidget",
        kind="PIPELINE",
        pipelineConfig={"functions": [function_id]},
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )

    got = svc.get_resolver(apiId=api_id, typeName="Query", fieldName="getWidget")["resolver"]
    assert got["kind"] == "PIPELINE"
    assert got["pipelineConfig"]["functions"] == [function_id]

    svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="getWidget")
    code, message = _error(lambda: svc.get_resolver(apiId=api_id, typeName="Query", fieldName="getWidget"))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code!r}"
    assert message == "No resolver found.", f"unexpected NotFoundException message {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
