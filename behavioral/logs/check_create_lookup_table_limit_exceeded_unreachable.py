"""create-lookup-table-limit-exceeded-unreachable."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-lookup-table-limit-exceeded-unreachable"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLookupTable returns a logs ARN and creation time, and GetLookupTable and DescribeLookupTables
    return the table with its exact name and body.
    """
    logs = ctx.client("logs")

    table_name = ctx.unique_name("sim2real_behav_lookup_").replace("-", "_")
    table_body = "id,label\n1,alpha\n2,beta\n"
    created = logs.create_lookup_table(lookupTableName=table_name, tableBody=table_body)
    table_arn = created["lookupTableArn"]
    ctx.on_cleanup(lambda: logs.delete_lookup_table(lookupTableArn=table_arn))

    assert table_arn.startswith("arn:aws:logs:"), (
        f"expected a well-formed lookup table ARN, got {table_arn!r}"
    )
    assert created["createdAt"] > 0, (
        f"expected a positive createdAt timestamp, got {created['createdAt']!r}"
    )

    fetched = logs.get_lookup_table(lookupTableArn=table_arn)
    assert fetched["lookupTableName"] == table_name, (
        f"expected GetLookupTable to return lookupTableName={table_name!r}, got {fetched['lookupTableName']!r}"
    )
    assert fetched["tableBody"] == table_body, (
        "the stored lookup table body should round-trip byte-for-byte"
    )

    listed = logs.describe_lookup_tables()["lookupTables"]
    assert any(t["lookupTableArn"] == table_arn for t in listed), (
        f"expected {table_arn} to appear in DescribeLookupTables, got {listed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
