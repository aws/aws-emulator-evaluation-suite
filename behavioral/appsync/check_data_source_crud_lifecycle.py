"""data-source-crud-lifecycle."""
from __future__ import annotations

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
    """Call fn(); return its (error code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

CHECK = "data-source-crud-lifecycle"
GROUP = 'data-source'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataSource -> Get/List reflect it -> UpdateDataSource persists -> DeleteDataSource -> Get is NotFound, mutation on the dead id fails, and the name is reusable."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    name = _sanitize(ctx.unique_name("sim2real-behav-ds_"))

    svc.create_data_source(apiId=api_id, name=name, type="NONE", description="v1")
    got = svc.get_data_source(apiId=api_id, name=name)["dataSource"]
    assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"
    assert got["type"] == "NONE", f"expected type NONE, got {got['type']!r}"
    assert got["description"] == "v1", f"expected description 'v1', got {got['description']!r}"

    names = [d["name"] for d in svc.list_data_sources(apiId=api_id)["dataSources"]]
    assert name in names, f"expected {name!r} in ListDataSources result {names}"

    svc.update_data_source(apiId=api_id, name=name, type="NONE", description="v2")
    got2 = svc.get_data_source(apiId=api_id, name=name)["dataSource"]
    assert got2["description"] == "v2", f"expected description 'v2' after update, got {got2['description']!r}"

    svc.delete_data_source(apiId=api_id, name=name)
    expected = ("NotFoundException", f"Data source {name} not found")
    error = _error(lambda: svc.get_data_source(apiId=api_id, name=name))
    assert error == expected, f"expected {expected} on GetDataSource after delete, got {error!r}"

    # A mutation against the dead id must also fail, not silently resurrect it.
    error2 = _error(lambda: svc.update_data_source(apiId=api_id, name=name, type="NONE", description="v3"))
    assert error2 == expected, f"expected {expected} on UpdateDataSource after delete, got {error2!r}"

    # The identifier is reusable once the original is gone.
    svc.create_data_source(apiId=api_id, name=name, type="NONE", description="v1-reused")
    ctx.on_cleanup(lambda _api_id=api_id, _name=name: svc.delete_data_source(apiId=_api_id, name=_name))
    got3 = svc.get_data_source(apiId=api_id, name=name)["dataSource"]
    assert got3["description"] == "v1-reused", f"expected reused name to accept a fresh create, got {got3!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
