"""resolver-kind-pipeline-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "resolver-kind-pipeline-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResolver with kind=UNIT while also supplying a pipelineConfig is rejected with
    BadRequestException, leaves no resolver behind, and a correctly-shaped UNIT resolver on
    the same API still succeeds (in-file positive control)."""
    appsync = ctx.client("appsync")
    api_name = ctx.unique_name("sim2real-resolverneg-")
    api = appsync.create_graphql_api(name=api_name, authenticationType="API_KEY")["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    appsync.start_schema_creation(
        apiId=api_id,
        definition=b"type Query { behavA: String behavB: String }",
    )
    _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=api_id)["status"],
        lambda status: status in ("SUCCESS", "FAILED"),
        timeout_s=60,
        interval_s=2,
    )
    schema_status = appsync.get_schema_creation_status(apiId=api_id)["status"]
    assert schema_status == "SUCCESS", f"expected schema creation SUCCESS, got {schema_status!r}"

    ds_name = "BehavNoneDS"
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))

    # Break exactly one thing: kind=UNIT with a pipelineConfig set is an invalid combination.
    code, message = _error(
        lambda: appsync.create_resolver(
            apiId=api_id,
            typeName="Query",
            fieldName="behavA",
            kind="UNIT",
            dataSourceName=ds_name,
            pipelineConfig={"functions": []},
            requestMappingTemplate="{}",
            responseMappingTemplate="$util.toJson($ctx.result)",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "PipelineConfig should not be specified.", f"unexpected BadRequestException message {message!r}"

    # (a)/(b): the invalid resolver was never created.
    not_found_code, not_found_message = _error(
        lambda: appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="behavA")
    )
    assert not_found_code == "NotFoundException", f"expected NotFoundException, got {not_found_code!r}"
    assert not_found_message == "No resolver found.", f"unexpected NotFoundException message {not_found_message!r}"

    # (c): a correctly-shaped UNIT resolver (no pipelineConfig) on the same API succeeds.
    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="behavB",
        kind="UNIT",
        dataSourceName=ds_name,
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )
    ctx.on_cleanup(lambda: appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="behavB"))
    ok_resolver = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="behavB")["resolver"]
    assert ok_resolver["kind"] == "UNIT", f"expected kind UNIT, got {ok_resolver['kind']!r}"
    assert ok_resolver["dataSourceName"] == ds_name, (
        f"expected dataSourceName {ds_name!r}, got {ok_resolver['dataSourceName']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
