"""resolver-pipeline-requires-config."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")

def _poll_until(probe, predicate, *, timeout_s=90, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "resolver-pipeline-requires-config"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateResolver with kind=PIPELINE but no pipelineConfig is rejected BadRequestException,
    no resolver is attached to the field (independent read), and the identical call with a
    valid pipelineConfig referencing a real function succeeds (positive control)."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real-behav": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    svc.start_schema_creation(
        apiId=api_id,
        definition=b"schema { query: Query }\ntype Query { echo: String }",
    )
    _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
        timeout_s=90,
        interval_s=2.0,
        description="schema creation to reach a terminal state",
    )

    ds_name = ctx.unique_name("sim2real_behav_ds_").replace("-", "_")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda _n=ds_name: svc.delete_data_source(apiId=api_id, name=_n))

    code, message = _error(
        lambda: svc.create_resolver(
            apiId=api_id,
            typeName="Query",
            fieldName="echo",
            kind="PIPELINE",
            requestMappingTemplate="{}",
            responseMappingTemplate="$util.toJson($ctx.result)",
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException for PIPELINE resolver without pipelineConfig, got {code}"
    )
    assert message == "PipelineConfig can't be null.", f"unexpected BadRequestException message {message!r}"

    absent_code, absent_message = _error(
        lambda: svc.get_resolver(apiId=api_id, typeName="Query", fieldName="echo")
    )
    assert absent_code == "NotFoundException", (
        f"expected no resolver attached to Query.echo after the rejected create, "
        f"got error {absent_code!r} from an independent get_resolver read"
    )
    assert absent_message == "No resolver found.", f"unexpected NotFoundException message {absent_message!r}"

    func_name = ctx.unique_name("sim2real_behav_fn_").replace("-", "_")
    func_id = svc.create_function(
        apiId=api_id,
        name=func_name,
        dataSourceName=ds_name,
        functionVersion="2018-05-29",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson({})",
    )["functionConfiguration"]["functionId"]
    ctx.on_cleanup(lambda _f=func_id: svc.delete_function(apiId=api_id, functionId=_f))

    good = svc.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="echo",
        kind="PIPELINE",
        pipelineConfig={"functions": [func_id]},
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )["resolver"]
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="echo"))
    assert good["pipelineConfig"]["functions"] == [func_id], (
        f"expected the positive control's pipelineConfig to reference {func_id!r}, "
        f"got {good.get('pipelineConfig')!r}"
    )

    fetched = svc.get_resolver(apiId=api_id, typeName="Query", fieldName="echo")["resolver"]
    assert (
        fetched["kind"] == "PIPELINE" and fetched["pipelineConfig"]["functions"] == [func_id]
    ), f"expected an independent read to confirm the pipeline resolver, got {fetched!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
