"""delete-data-source-in-use-blocked."""
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
    """Call fn(); return its (error code, message, HTTP status). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), err.get("Message") or "", status
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _assert_not_found(got, name, label, expected_message):
    """NotFoundException + 404 with a message naming the data source (AWS names it)."""
    code, message, status = got
    assert (code, status) == ("NotFoundException", 404), (
        f"{label}: expected NotFoundException/404, got {code!r}/{status!r}"
    )
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


def _data_source_names(svc, api_id):
    """Every data source name on the api, following nextToken."""
    names, kwargs = [], {}
    while True:
        page = svc.list_data_sources(apiId=api_id, **kwargs)
        names.extend(d["name"] for d in page["dataSources"])
        if not page.get("nextToken"):
            return names
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

CHECK = "delete-data-source-in-use-blocked"
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
    """DeleteDataSource on a source still referenced by a resolver must fail BadRequestException,
    leaving the data source intact; once the resolver is removed the identical delete succeeds and
    the data source becomes unreadable and undeletable."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real-check": CHECK},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    svc.start_schema_creation(apiId=api_id, definition=DEFAULT_SCHEMA)
    _sc = _poll_until(lambda: svc.get_schema_creation_status(apiId=api_id), lambda r: r.get("status") in ("SUCCESS", "ACTIVE", "FAILED"), timeout_s=60, interval_s=1.5, description="schema creation")
    if _sc.get("status") == "FAILED":
        raise AssertionError(f"schema creation failed: {_sc.get('details')}")

    # Positive control: an unreferenced data source of the same type deletes cleanly, so the
    # BadRequestException below is attributable to the resolver reference, not to a broken delete path.
    control_name = _sanitize(ctx.unique_name("sim2real-behav-ds-control_"))
    svc.create_data_source(apiId=api_id, name=control_name, type="NONE")
    svc.delete_data_source(apiId=api_id, name=control_name)
    _assert_not_found(
        _error(lambda: svc.get_data_source(apiId=api_id, name=control_name)), control_name,
        "GetDataSource on the deleted control data source",
        expected_message=f"Data source {control_name} not found",
    )

    ds = svc.create_data_source(apiId=api_id, name=_sanitize(ctx.unique_name("sim2real-behav-ds_")), type="NONE")["dataSource"]
    ds_name = ds["name"]

    svc.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="getWidget",
        dataSourceName=ds_name,
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )

    code, message, status = _error(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    assert (code, status) == ("BadRequestException", 400), (
        f"expected DeleteDataSource on a referenced source to be BadRequestException/400, got {code!r}/{status!r}"
    )
    expected_message = "Resolver for type Query and field getWidget associated with data source"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # effect absent: the rejected delete left the data source intact and independently readable
    still_there = svc.get_data_source(apiId=api_id, name=ds_name)["dataSource"]
    assert still_there["name"] == ds_name, f"data source should still exist after rejected delete, got {still_there}"

    # restore: once the resolver is gone, the identical delete call now succeeds
    svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="getWidget")
    svc.delete_data_source(apiId=api_id, name=ds_name)

    # deletes prove gone and unusable: an independent read 404s, and a further mutation on the
    # dead id also fails rather than silently no-op'ing
    _assert_not_found(
        _error(lambda: svc.get_data_source(apiId=api_id, name=ds_name)), ds_name, "GetDataSource after delete",
        expected_message=f"Data source {ds_name} not found",
    )
    listed = _data_source_names(svc, api_id)
    for name in (ds_name, control_name):
        assert name not in listed, f"expected deleted data source {name!r} absent from ListDataSources, got {listed!r}"
    _assert_not_found(
        _error(lambda: svc.delete_data_source(apiId=api_id, name=ds_name)), ds_name, "DeleteDataSource re-delete",
        expected_message=f"Data source {ds_name} not found",
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
