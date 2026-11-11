"""cross-api-resolver-datasource-isolation-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cross-api-resolver-datasource-isolation-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]

_SCHEMA = "type Query {\n  field: String\n  controlField: String\n}\n"
_REQUEST_TEMPLATE = '{"version":"2018-05-29","payload":{}}'
_RESPONSE_TEMPLATE = '$util.toJson("x")'


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A resolver on API B naming a data source that exists only on API A fails NotFoundException:
    data source names are scoped to their API. A resolver bound to API B's own data source succeeds."""
    appsync = ctx.client("appsync")
    api_a = _create_graphql_api(ctx)
    api_a_id = api_a["apiId"]
    api_b = _create_graphql_api(ctx)
    api_b_id = api_b["apiId"]

    _start_schema_and_wait(ctx, api_a_id, _SCHEMA)
    _start_schema_and_wait(ctx, api_b_id, _SCHEMA)

    ds_name = _create_none_datasource(ctx, api_a_id)
    # ds_name exists on api_a only; api_b has no data source with this name.
    own_ds_name = _create_none_datasource(ctx, api_b_id)

    # positive control: a resolver on api_b bound to a data source that genuinely
    # exists on api_b must succeed.
    appsync.create_resolver(
        apiId=api_b_id,
        typeName="Query",
        fieldName="controlField",
        dataSourceName=own_ds_name,
        kind="UNIT",
        requestMappingTemplate=_REQUEST_TEMPLATE,
        responseMappingTemplate=_RESPONSE_TEMPLATE,
    )

    error = _error(
        lambda: appsync.create_resolver(
            apiId=api_b_id,
            typeName="Query",
            fieldName="field",
            dataSourceName=ds_name,
            kind="UNIT",
            requestMappingTemplate=_REQUEST_TEMPLATE,
            responseMappingTemplate=_RESPONSE_TEMPLATE,
        )
    )
    expected = ("NotFoundException", f"No data source found named {ds_name}")
    assert error == expected, (
        f"expected {expected} for cross-API data source reference, got {error}"
    )

    resolvers_b = appsync.list_resolvers(apiId=api_b_id, typeName="Query")["resolvers"]
    field_names_b = {r["fieldName"] for r in resolvers_b}
    assert field_names_b == {"controlField"}, (
        f"expected only the positive-control resolver on api_b, got {field_names_b}"
    )


def _error(fn):
    """Call fn(); return its (error code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_graphql_api(ctx, auth_type="API_KEY"):
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType=auth_type,
        tags={"sim2real": CHECK},
    )
    api = resp["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api


def _start_schema_and_wait(ctx, api_id, definition, timeout_s=120.0, interval_s=3.0):
    appsync = ctx.client("appsync")
    appsync.start_schema_creation(apiId=api_id, definition=definition.encode("utf-8"))
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = appsync.get_schema_creation_status(apiId=api_id)
        status = resp["status"]
        if status in ("SUCCESS", "ACTIVE"):
            return status
        if status == "FAILED":
            raise AssertionError(f"schema creation FAILED: {resp.get('details')}")
        time.sleep(interval_s)
    raise AssertionError(f"schema creation incomplete after {timeout_s}s, last={status}")


def _create_none_datasource(ctx, api_id, name=None):
    appsync = ctx.client("appsync")
    ds_name = name or ctx.unique_name("sim2real_ds_").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    return ds_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
