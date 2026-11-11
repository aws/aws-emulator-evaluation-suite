"""op-contract-updatePreparedStatement."""
from __future__ import annotations

CHECK = "op-contract-updatePreparedStatement"
GROUP = "error-semantics"
SERVICES = ["athena"]

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp is not None:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePreparedStatement overwrites QueryStatement/Description in the workgroup; unknown StatementName is rejected."""
    athena = ctx.client("athena")

    wg_name = ctx.unique_name("sim2real-behav-wg-")
    athena.create_work_group(Name=wg_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name))

    statement_name = ctx.unique_name("sim2real_behav_stmt_")
    athena.create_prepared_statement(
        StatementName=statement_name,
        WorkGroup=wg_name,
        QueryStatement="SELECT 1",
        Description="original description",
    )
    ctx.on_cleanup(
        lambda: athena.delete_prepared_statement(StatementName=statement_name, WorkGroup=wg_name)
    )

    before = athena.get_prepared_statement(StatementName=statement_name, WorkGroup=wg_name)[
        "PreparedStatement"
    ]
    assert before["QueryStatement"] == "SELECT 1"
    assert before["Description"] == "original description"

    athena.update_prepared_statement(
        StatementName=statement_name,
        WorkGroup=wg_name,
        QueryStatement="SELECT 2",
        Description="updated description",
    )
    after = athena.get_prepared_statement(StatementName=statement_name, WorkGroup=wg_name)[
        "PreparedStatement"
    ]
    assert after["QueryStatement"] == "SELECT 2", after
    assert after["Description"] == "updated description", after
    # Identity fields unchanged by the update.
    assert after["StatementName"] == statement_name
    assert after["WorkGroupName"] == wg_name

    # Error boundary: StatementName that was never created in this workgroup.
    missing_statement = ctx.unique_name("sim2real_behav_missing_stmt_")
    code, message = _error(
        lambda: athena.update_prepared_statement(
            StatementName=missing_statement, WorkGroup=wg_name, QueryStatement="SELECT 3"
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    # AWS ends this message with a trailing space.
    assert message == (
        f"Prepared Statement {missing_statement} does not exist in WorkGroup {wg_name} "
    ), repr(message)

    # No prepared statement was created as a side effect of the failed update.
    code2, message2 = _error(
        lambda: athena.get_prepared_statement(StatementName=missing_statement, WorkGroup=wg_name)
    )
    assert code2 == "ResourceNotFoundException", f"expected {missing_statement} to not exist, got {code2}"
    assert message2 == (
        f"No Prepared Statement with statement name {missing_statement} exists in WorkGroup {wg_name}"
    ), repr(message2)

    # The real prepared statement is unaffected by the failed call above.
    still = athena.get_prepared_statement(StatementName=statement_name, WorkGroup=wg_name)[
        "PreparedStatement"
    ]
    assert still["QueryStatement"] == "SELECT 2"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
