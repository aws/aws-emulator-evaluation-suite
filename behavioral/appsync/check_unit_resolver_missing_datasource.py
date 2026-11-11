"""unit-resolver-missing-datasource."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "unit-resolver-missing-datasource"
GROUP = 'overly-permissive'
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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateResolver(kind=UNIT) without dataSourceName and without pipelineConfig must fail
    BadRequestException, leave no resolver attached to the field, and a correctly-shaped UNIT
    resolver (with dataSourceName) on the same API must still succeed (positive control)."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    svc.start_schema_creation(apiId=api_id, definition=DEFAULT_SCHEMA)
    _sc = _poll_until(lambda: svc.get_schema_creation_status(apiId=api_id), lambda r: r.get("status") in ("SUCCESS", "ACTIVE", "FAILED"), timeout_s=60, interval_s=1.5, description="schema creation")
    if _sc.get("status") == "FAILED":
        raise AssertionError(f"schema creation failed: {_sc.get('details')}")

    ds_name = "noneDs"
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")

    def attempt():
        return svc.create_resolver(
            apiId=api_id,
            typeName="Query",
            fieldName="getWidget",
            kind="UNIT",
            requestMappingTemplate="{}",
            responseMappingTemplate="$util.toJson($ctx.result)",
        )

    code, msg = _error(attempt)
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert msg == "Data source name not specified.", f"unexpected message: {msg!r}"

    absent_code, absent_msg = _error(lambda: svc.get_resolver(apiId=api_id, typeName="Query", fieldName="getWidget"))
    assert absent_code == "NotFoundException", f"expected no resolver attached after rejected create, got {absent_code}"
    assert absent_msg == "No resolver found.", f"unexpected message: {absent_msg!r}"

    good = svc.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getWidget2",
        kind="UNIT",
        dataSourceName=ds_name,
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )["resolver"]
    ctx.on_cleanup(lambda _a=api_id: svc.delete_resolver(apiId=_a, typeName="Query", fieldName="getWidget2"))
    assert good["kind"] == "UNIT", f"positive control: expected kind UNIT, got {good.get('kind')}"
    assert good["dataSourceName"] == ds_name, (
        f"positive control: expected dataSourceName {ds_name!r}, got {good.get('dataSourceName')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
