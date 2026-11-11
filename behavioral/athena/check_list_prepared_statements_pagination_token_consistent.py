"""list-prepared-statements-pagination-token-consistent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-prepared-statements-pagination-token-consistent"
GROUP = "ordering"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPreparedStatements pagination (MaxResults + NextToken) resumes from the exact offset:
    paging through with a small page size returns the same names, in the same order, as a single
    unpaginated call, with no entry duplicated or skipped across pages."""
    athena = ctx.client("athena")
    wg_name = ctx.unique_name("sim2real-behav-ps-wg-")
    athena.create_work_group(Name=wg_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    created_names = []
    for i in range(6):
        stmt_name = ctx.unique_name(f"sim2real_behav_ps_{i}_").replace("-", "_")
        athena.create_prepared_statement(
            StatementName=stmt_name,
            WorkGroup=wg_name,
            QueryStatement=f"SELECT {i}",
        )
        created_names.append(stmt_name)

    full = athena.list_prepared_statements(WorkGroup=wg_name, MaxResults=50)
    assert "NextToken" not in full, "expected all 6 prepared statements to fit on one page of 50"
    full_names = [p["StatementName"] for p in full["PreparedStatements"]]
    for name in created_names:
        assert name in full_names, f"created prepared statement {name} missing from unpaginated listing {full_names}"

    paged_names: list[str] = []
    token = None
    page_count = 0
    while True:
        kwargs = {"WorkGroup": wg_name, "MaxResults": 2}
        if token:
            kwargs["NextToken"] = token
        resp = athena.list_prepared_statements(**kwargs)
        page_count += 1
        paged_names.extend(p["StatementName"] for p in resp["PreparedStatements"])
        token = resp.get("NextToken")
        if not token:
            break

    assert page_count >= 3, f"expected at least 3 pages of size 2 for 6 items, got {page_count}"
    assert len(paged_names) == len(set(paged_names)), (
        f"pagination produced duplicated entries: {paged_names}"
    )
    assert paged_names == full_names, (
        "paginated ListPreparedStatements does not resume from the exact offset of the "
        f"unpaginated order: paged={paged_names} full={full_names}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
