"""prepared-statement-update-reflected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "prepared-statement-update-reflected"
GROUP = "prepared-statement"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePreparedStatement replaces the QueryStatement/Description in place; a subsequent
    GetPreparedStatement returns the new text exactly, not the original."""
    athena = ctx.client("athena")
    wg_name = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=wg_name)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    stmt_name = ctx.unique_name("sim2real_stmt_").replace("-", "_")
    athena.create_prepared_statement(
        StatementName=stmt_name,
        WorkGroup=wg_name,
        QueryStatement="SELECT 1",
        Description="v1",
    )
    ctx.on_cleanup(lambda: athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup=wg_name))

    original = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg_name)["PreparedStatement"]
    assert original["QueryStatement"] == "SELECT 1", original
    assert original["Description"] == "v1", original

    athena.update_prepared_statement(
        StatementName=stmt_name,
        WorkGroup=wg_name,
        QueryStatement="SELECT 2",
        Description="v2",
    )
    updated = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg_name)["PreparedStatement"]
    assert updated["QueryStatement"] == "SELECT 2", updated
    assert updated["Description"] == "v2", updated
    assert updated["StatementName"] == stmt_name, updated
    assert updated["WorkGroupName"] == wg_name, updated


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
