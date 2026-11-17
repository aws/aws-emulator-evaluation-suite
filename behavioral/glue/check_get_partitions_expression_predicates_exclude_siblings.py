"""get-partitions-expression-predicates-exclude-siblings."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-partitions-expression-predicates-exclude-siblings"
GROUP = 'partition'
SERVICES = ['glue']


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """get_partitions filters an int partition key by equality, IN, range and a
    non-matching value against one table with four partitions; each predicate
    excludes at least one sibling partition, and a value nothing matches returns [].
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    tbl_name = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://example-bucket/data/",
            },
            "PartitionKeys": [{"Name": "year", "Type": "int"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    years = ("2025", "2026", "2027", "2028")
    resp = glue.batch_create_partition(
        DatabaseName=db_name,
        TableName=tbl_name,
        PartitionInputList=[{"Values": [y]} for y in years],
    )
    assert resp.get("Errors", []) == [], (
        f"expected no per-entry errors creating {years}, got {resp.get('Errors')}"
    )

    def _get(expression: str) -> list[str]:
        pages = glue.get_paginator("get_partitions").paginate(
            DatabaseName=db_name, TableName=tbl_name, Expression=expression
        )
        return sorted(p["Values"][0] for page in pages for p in page["Partitions"])

    equals = _get("year = 2026")
    assert equals == ["2026"], (
        f"'year = 2026' against partitions {years} must return exactly ['2026'], got {equals}"
    )

    in_list = _get("year in (2026, 2028)")
    assert in_list == ["2026", "2028"], (
        f"'year in (2026, 2028)' against partitions {years} must return exactly "
        f"['2026', '2028'], got {in_list}"
    )

    range_ = _get("year >= 2026 AND year <= 2027")
    assert range_ == ["2026", "2027"], (
        f"'year >= 2026 AND year <= 2027' against partitions {years} must return exactly "
        f"['2026', '2027'], got {range_}"
    )

    empty = _get("year in (1999)")
    assert empty == [], (
        f"'year in (1999)', a value no partition carries, must return [], got {empty}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
