"""get-partitions-segmented-scan-complete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-partitions-segmented-scan-complete"
GROUP = 'partition'
SERVICES = ['glue']


def _storage(columns, location="s3://example-bucket/data/"):
    return {
        "Columns": columns,
        "Location": location,
        "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
        "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
        "SerdeInfo": {
            "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
        },
    }


def _drain(glue, db_name, tbl_name, segment=None):
    """All partition values for one (optionally segmented) scan, paging to exhaustion."""
    values = []
    token = None
    for _ in range(20):
        kwargs = {"DatabaseName": db_name, "TableName": tbl_name}
        if segment is not None:
            kwargs["Segment"] = segment
        if token:
            kwargs["NextToken"] = token
        resp = glue.get_partitions(**kwargs)
        values.extend(p["Values"][0] for p in resp["Partitions"])
        token = resp.get("NextToken")
        if not token:
            return values
    raise AssertionError(f"segmented scan {segment} did not terminate in 20 pages: {values}")


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A 2-way segmented GetPartitions scan is complete and disjoint: no segment repeats a
    partition, the segments share none, and together they return exactly every partition.
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    tbl_name = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": _storage([{"Name": "id", "Type": "bigint"}]),
            "PartitionKeys": [{"Name": "dt", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    expected = ["2024-02-0%d" % i for i in range(1, 7)]
    for dt in expected:
        glue.create_partition(
            DatabaseName=db_name,
            TableName=tbl_name,
            PartitionInput={
                "Values": [dt],
                "StorageDescriptor": _storage(
                    [{"Name": "id", "Type": "bigint"}],
                    location="s3://example-bucket/data/dt=%s/" % dt,
                ),
            },
        )

    # Control: the unsegmented scan is the ground truth for this table.
    whole = _drain(glue, db_name, tbl_name)
    assert sorted(whole) == expected, (
        f"unsegmented scan must return all 6 partitions, got {sorted(whole)}"
    )

    seg0 = _drain(glue, db_name, tbl_name, {"SegmentNumber": 0, "TotalSegments": 2})
    seg1 = _drain(glue, db_name, tbl_name, {"SegmentNumber": 1, "TotalSegments": 2})

    assert len(seg0) == len(set(seg0)), f"segment 0 returned duplicates: {seg0}"
    assert len(seg1) == len(set(seg1)), f"segment 1 returned duplicates: {seg1}"
    overlap = set(seg0) & set(seg1)
    assert overlap == set(), (
        f"segments must be disjoint; both returned {sorted(overlap)} "
        f"(seg0={sorted(seg0)} seg1={sorted(seg1)})"
    )
    assert sorted(seg0 + seg1) == expected, (
        f"segments must together cover every partition exactly once: "
        f"{sorted(seg0 + seg1)} != {expected}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
