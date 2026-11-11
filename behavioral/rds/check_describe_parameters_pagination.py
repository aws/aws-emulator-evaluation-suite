"""describe-parameters-pagination."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-parameters-pagination"
GROUP = 'parameter_groups'
SERVICES = ['rds']

@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBParameters walks the Marker across the full mysql8.0 parameter set with no gaps or repeats."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-pg-")
    rds.create_db_parameter_group(
        DBParameterGroupName=name,
        DBParameterGroupFamily="mysql8.0",
        Description="sim2real behavioral test parameter group",
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=name))

    first = rds.describe_db_parameters(DBParameterGroupName=name, MaxRecords=20)
    assert len(first["Parameters"]) == 20, (
        f"expected exactly 20 parameters on the first page (MaxRecords=20), "
        f"got {len(first['Parameters'])}"
    )
    assert "Marker" in first, (
        "expected a continuation Marker: mysql8.0 has hundreds of parameters, "
        "more than fit in one 20-record page"
    )

    pages = [{p["ParameterName"] for p in first["Parameters"]}]
    marker = first["Marker"]
    while marker is not None:
        assert len(pages) < 100, "pagination did not terminate within 100 pages"
        page = rds.describe_db_parameters(
            DBParameterGroupName=name, MaxRecords=20, Marker=marker
        )
        page_names = {p["ParameterName"] for p in page["Parameters"]}
        assert page_names, f"page {len(pages) + 1} returned no parameters while continuing a Marker"
        pages.append(page_names)
        marker = page.get("Marker")

    assert len(pages) > 1, "expected more than one page for mysql8.0's parameter set"

    all_names: set[str] = set()
    for i, page_names in enumerate(pages):
        overlap = all_names & page_names
        assert not overlap, f"page {i + 1} repeated parameters instead of advancing: {sorted(overlap)[:5]}"
        all_names |= page_names

    full = rds.get_paginator("describe_db_parameters").paginate(
        DBParameterGroupName=name
    ).build_full_result()
    full_names = {p["ParameterName"] for p in full["Parameters"]}
    assert all_names == full_names, (
        f"walking Marker by hand collected {len(all_names)} distinct parameters but "
        f"the built-in paginator reports {len(full_names)}: "
        f"missing={sorted(full_names - all_names)[:5]} extra={sorted(all_names - full_names)[:5]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
