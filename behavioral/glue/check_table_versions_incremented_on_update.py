"""table-versions-incremented-on-update."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "table-versions-incremented-on-update"
GROUP = 'table'
SERVICES = ['glue']

def _table_input(tbl_name: str, description: str) -> dict:
    return {
        "Name": tbl_name,
        "Description": description,
        "StorageDescriptor": {
            "Columns": [{"Name": "col1", "Type": "string"}],
            "Location": "s3://example-bucket/data/",
        },
        "PartitionKeys": [{"Name": "year", "Type": "string"}],
    }


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each update_table call creates a new, independently retrievable table version
    that carries the content as of that call — not just a new id."""
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(
        DatabaseInput={"Name": db_name}, Tags={"sim2real-behav": "table-versions-incremented-on-update"}
    )
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    tbl_name = ctx.unique_name("sim2real-behav-tbl-")
    descriptions = ["created", "updated-0", "updated-1"]
    glue.create_table(DatabaseName=db_name, TableInput=_table_input(tbl_name, descriptions[0]))
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    for desc in descriptions[1:]:
        glue.update_table(DatabaseName=db_name, TableInput=_table_input(tbl_name, desc))

    versions = glue.get_table_versions(DatabaseName=db_name, TableName=tbl_name)["TableVersions"]
    by_id = {v["VersionId"]: v["Table"] for v in versions}
    assert len(by_id) == len(descriptions), (
        f"expected exactly {len(descriptions)} versions (create + {len(descriptions) - 1} "
        f"updates), got {sorted(by_id)}"
    )
    seen_descriptions = {t.get("Description") for t in by_id.values()}
    assert seen_descriptions == set(descriptions), (
        f"expected one version per call carrying {descriptions}, got {seen_descriptions}"
    )

    live = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"]
    assert live["Description"] == descriptions[-1], (
        f"expected live table to reflect the most recent update {descriptions[-1]!r}, "
        f"got {live.get('Description')!r}"
    )
    assert live["VersionId"] in by_id, (
        f"expected the live table's VersionId {live.get('VersionId')!r} to be one of the "
        f"versions returned by get_table_versions {sorted(by_id)}"
    )
    assert by_id[live["VersionId"]]["Description"] == descriptions[-1], (
        f"expected the version get_table_versions labels as the live VersionId "
        f"{live['VersionId']!r} to carry the latest content, got "
        f"{by_id[live['VersionId']].get('Description')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
