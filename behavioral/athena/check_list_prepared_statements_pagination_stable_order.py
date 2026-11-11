"""list-prepared-statements-pagination-stable-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-prepared-statements-pagination-stable-order"
GROUP = "ordering"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPreparedStatements pagination tokens return each created prepared statement
    exactly once, with no gaps or duplicates, and a stable order across repeated calls."""
    athena = ctx.client("athena")

    wg_name = ctx.unique_name("sim2real-wg-")
    athena.create_work_group(Name=wg_name)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name))

    created_names: list[str] = []
    for i in range(6):
        stmt_name = ctx.unique_name(f"sim2real_stmt_{i}_").replace("-", "_")
        athena.create_prepared_statement(
            StatementName=stmt_name, WorkGroup=wg_name, QueryStatement=f"SELECT {i}"
        )
        created_names.append(stmt_name)
        ctx.on_cleanup(
            lambda stmt_name=stmt_name: athena.delete_prepared_statement(
                StatementName=stmt_name, WorkGroup=wg_name
            )
        )

    first_pass, first_pages = _list_all_prepared_statements(athena, wg_name)
    second_pass, _ = _list_all_prepared_statements(athena, wg_name)

    assert first_pages >= 3, (
        f"expected at least 3 pages of size 2 for {len(created_names)} prepared statements, "
        f"got {first_pages} — MaxResults appears to have been ignored"
    )

    for name in created_names:
        count = first_pass.count(name)
        assert count == 1, f"expected prepared statement {name} exactly once, saw {count}"

    assert len(first_pass) == len(set(first_pass)), "ListPreparedStatements returned a duplicate StatementName across pages"
    assert first_pass == second_pass, "ListPreparedStatements pagination order changed across repeated calls"


def _list_all_prepared_statements(athena, workgroup: str) -> tuple[list[str], int]:
    names: list[str] = []
    token = None
    pages = 0
    while True:
        kwargs = {"WorkGroup": workgroup, "MaxResults": 2}
        if token:
            kwargs["NextToken"] = token
        resp = athena.list_prepared_statements(**kwargs)
        pages += 1
        names.extend(p["StatementName"] for p in resp.get("PreparedStatements", []))
        token = resp.get("NextToken")
        if not token:
            break
    return names, pages


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
