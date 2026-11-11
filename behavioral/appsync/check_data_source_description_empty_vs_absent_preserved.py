"""data-source-description-empty-vs-absent-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "data-source-description-empty-vs-absent-preserved"
GROUP = "data-source"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AppSync normalizes an explicit empty-string DataSource description to absent: GetDataSource
    returns no "description" key, exactly as for a sibling created without one.
    """
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    name_empty = _safe_name(ctx, "dsempty")
    name_absent = _safe_name(ctx, "dsabsent")

    appsync.create_data_source(apiId=api_id, name=name_empty, type="NONE", description="")
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=name_empty))

    appsync.create_data_source(apiId=api_id, name=name_absent, type="NONE")
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=name_absent))

    ds_empty = appsync.get_data_source(apiId=api_id, name=name_empty)["dataSource"]
    ds_absent = appsync.get_data_source(apiId=api_id, name=name_absent)["dataSource"]

    assert ds_empty.get("description") is None, (
        f"explicit empty-string description was NOT normalized to absent: "
        f"got={ds_empty.get('description')!r}"
    )
    assert ds_absent.get("description") is None, (
        f"got={ds_absent.get('description')!r}"
    )
    # The rest of each data source is populated, so the missing key is not a wider omission.
    assert ds_empty["name"] == name_empty and ds_empty["type"] == "NONE", (
        f"ds_empty otherwise malformed: name={ds_empty.get('name')!r} type={ds_empty.get('type')!r}"
    )
    assert ds_absent["name"] == name_absent and ds_absent["type"] == "NONE", (
        f"ds_absent otherwise malformed: name={ds_absent.get('name')!r} type={ds_absent.get('type')!r}"
    )



def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(name=name, authenticationType="API_KEY")
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _safe_name(ctx, kind: str) -> str:
    # AppSync data source names must match ^[_A-Za-z][_0-9A-Za-z]*$ (no hyphens).
    raw = ctx.unique_name(f"sim2real{kind}")
    return "".join(c if c.isalnum() or c == "_" else "_" for c in raw)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
