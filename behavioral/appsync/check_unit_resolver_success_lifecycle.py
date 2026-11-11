"""unit-resolver-success-lifecycle."""
from __future__ import annotations

import time
import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _sanitize(name):
    """AppSync data source/function names must match ^[_A-Za-z][_0-9A-Za-z]*$."""
    cleaned = re.sub(r"[^0-9A-Za-z_]", "_", name)
    if not cleaned or not re.match(r"[_A-Za-z]", cleaned[0]):
        cleaned = "n_" + cleaned
    return cleaned

def _error(fn):
    """Call fn(); return the (code, message, HTTP status) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), err.get("Message") or "", status
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _query_resolver_fields(svc, api_id):
    """Every Query resolver's fieldName on the api, following nextToken."""
    fields, kwargs = [], {}
    while True:
        page = svc.list_resolvers(apiId=api_id, typeName="Query", **kwargs)
        fields.extend(r["fieldName"] for r in page["resolvers"])
        if not page.get("nextToken"):
            return fields
        kwargs = {"nextToken": page["nextToken"]}


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "unit-resolver-success-lifecycle"
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

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResolver(kind=UNIT) -> Get/Update/List -> DeleteResolver -> not-found, unlisted, update refused."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(name=ctx.unique_name("sim2real-behav-appsync-api-"), authenticationType="API_KEY", tags={"env": "test"})["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    svc.start_schema_creation(apiId=api_id, definition=DEFAULT_SCHEMA)
    _sc = _poll_until(lambda: svc.get_schema_creation_status(apiId=api_id), lambda r: r.get("status") in ("SUCCESS", "ACTIVE", "FAILED"), timeout_s=60, interval_s=1.5, description="schema creation")
    if _sc.get("status") == "FAILED":
        raise AssertionError(f"schema creation failed: {_sc.get('details')}")
    ds = svc.create_data_source(apiId=api_id, name=_sanitize(ctx.unique_name("sim2real-behav-ds_")), type="NONE")["dataSource"]
    ds_name = ds["name"]

    svc.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getWidget",
        kind="UNIT",
        dataSourceName=ds_name,
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )

    got = svc.get_resolver(apiId=api_id, typeName="Query", fieldName="getWidget")["resolver"]
    assert got["kind"] == "UNIT", f"expected kind UNIT, got {got.get('kind')!r}"
    assert got["dataSourceName"] == ds_name, f"expected dataSourceName {ds_name!r}, got {got.get('dataSourceName')!r}"

    new_response = '{"widget": $util.toJson($ctx.result)}'
    svc.update_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getWidget",
        kind="UNIT",
        dataSourceName=ds_name,
        requestMappingTemplate="{}",
        responseMappingTemplate=new_response,
    )
    got = svc.get_resolver(apiId=api_id, typeName="Query", fieldName="getWidget")["resolver"]
    assert got.get("responseMappingTemplate") == new_response, (
        f"expected the updated responseMappingTemplate {new_response!r}, got {got.get('responseMappingTemplate')!r}"
    )
    fields = _query_resolver_fields(svc, api_id)
    assert "getWidget" in fields, f"expected getWidget in ListResolvers(Query), got {fields!r}"

    svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="getWidget")
    code, msg, status = _error(lambda: svc.get_resolver(apiId=api_id, typeName="Query", fieldName="getWidget"))
    assert (code, status) == ("NotFoundException", 404), (
        f"expected NotFoundException/404 reading a deleted resolver, got {code!r}/{status!r}"
    )
    expected_message = "No resolver found."
    assert msg == expected_message, f"expected the message {expected_message!r}, got {msg!r}"

    fields = _query_resolver_fields(svc, api_id)
    assert "getWidget" not in fields, f"expected getWidget absent from ListResolvers(Query) after delete, got {fields!r}"

    update_code, update_msg, update_status = _error(lambda: svc.update_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getWidget",
        dataSourceName=ds_name,
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    ))
    assert (update_code, update_status) == ("NotFoundException", 404), (
        f"expected NotFoundException/404 updating a deleted resolver, got {update_code!r}/{update_status!r}"
    )
    expected_message = "No resolver found."
    assert update_msg == expected_message, f"expected the message {expected_message!r}, got {update_msg!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
