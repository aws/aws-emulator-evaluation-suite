"""op-contract-batch-get-prepared-statement."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-batch-get-prepared-statement"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetPreparedStatement returns full statement bodies for known names and
    lists unknown names under UnprocessedPreparedStatementNames instead of raising."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-wg-")
    athena.create_work_group(Name=wg, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg))

    names = []
    for i in range(2):
        name = ctx.unique_name(f"sim2real_ps_{i}_")
        athena.create_prepared_statement(
            StatementName=name,
            WorkGroup=wg,
            QueryStatement=f"SELECT {i} AS col",
        )
        names.append(name)
        ctx.on_cleanup(lambda name=name: athena.delete_prepared_statement(StatementName=name, WorkGroup=wg))

    bogus_name = "sim2real_ps_missing_00000"
    resp = athena.batch_get_prepared_statement(PreparedStatementNames=names + [bogus_name], WorkGroup=wg)

    returned = {ps["StatementName"]: ps for ps in resp["PreparedStatements"]}
    assert set(returned) == set(names), f"expected {names}, got {list(returned)}"
    for i, name in enumerate(names):
        expected_stmt = f"SELECT {i} AS col"
        assert returned[name]["QueryStatement"] == expected_stmt, (
            f"{name}: expected QueryStatement {expected_stmt!r}, got {returned[name]['QueryStatement']!r}"
        )
        assert returned[name]["WorkGroupName"] == wg, (
            f"{name}: expected WorkGroupName {wg!r}, got {returned[name]['WorkGroupName']!r}"
        )

    unprocessed = resp["UnprocessedPreparedStatementNames"]
    assert len(unprocessed) == 1, f"expected 1 unprocessed name, got {unprocessed}"
    assert unprocessed[0]["StatementName"] == bogus_name, (
        f"expected unprocessed name {bogus_name!r}, got {unprocessed[0]['StatementName']!r}"
    )
    assert unprocessed[0]["ErrorCode"], "unprocessed entry must carry an ErrorCode"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
