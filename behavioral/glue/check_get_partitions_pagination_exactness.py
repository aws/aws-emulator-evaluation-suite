"""get-partitions-pagination-exactness."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-partitions-pagination-exactness"
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


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPartitions with MaxResults=2 over 5 partitions returns pages of at most 2 across 3 to 6
    calls, no empty page before the last, and every partition exactly once, as unpaged.
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
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": _storage([{"Name": "id", "Type": "bigint"}]),
            "PartitionKeys": [{"Name": "dt", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    expected = ["2024-01-0%d" % i for i in range(1, 6)]
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

    unpaged = glue.get_partitions(DatabaseName=db_name, TableName=tbl_name)
    assert sorted(p["Values"][0] for p in unpaged["Partitions"]) == expected, (
        f"unpaged GetPartitions must return all 5 partitions, got {unpaged['Partitions']}"
    )

    pages = []
    token = None
    for _ in range(12):  # bounded: 5 partitions at 2/page cannot need more than 3-4 calls
        kwargs = {"DatabaseName": db_name, "TableName": tbl_name, "MaxResults": 2}
        if token:
            kwargs["NextToken"] = token
        resp = glue.get_partitions(**kwargs)
        pages.append([p["Values"][0] for p in resp["Partitions"]])
        token = resp.get("NextToken")
        if not token:
            break
    assert not token, (
        f"pagination did not terminate within 12 calls; pages so far: {pages}"
    )

    for i, page in enumerate(pages):
        assert len(page) <= 2, (
            f"MaxResults=2 was ignored: page {i} returned {len(page)} partitions ({page})"
        )
    assert len(pages) >= 3, (
        f"5 partitions at MaxResults=2 must span at least 3 pages, got {len(pages)}: {pages}"
    )
    # MaxResults is an upper bound: a non-final page may be short and the chain may end with an
    # empty page, so only non-empty pages before the last and at most one page per partition plus
    # that terminator are asserted.
    for i, page in enumerate(pages[:-1]):
        assert page, (
            f"a non-final page (one that returned a NextToken) must not be empty; page {i} "
            f"of {pages}"
        )
    assert len(pages) <= len(expected) + 1, (
        f"{len(pages)} pages for {len(expected)} partitions means the NextToken chain is "
        f"restarting or stalling: {pages}"
    )

    seen = [v for page in pages for v in page]
    assert len(seen) == len(set(seen)), f"pagination returned duplicates: {seen}"
    assert sorted(seen) == expected, (
        f"paginated union must equal the unpaged set exactly: {sorted(seen)} != {expected}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
