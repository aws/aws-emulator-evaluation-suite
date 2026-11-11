"""op-contract-update-prepared-statement-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-update-prepared-statement-rejected"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePreparedStatement overwrites QueryStatement/Description of an existing prepared
    statement in place; updating a StatementName that was never created in a real WorkGroup is
    rejected with ResourceNotFoundException and leaves the real statement untouched.
    """
    athena = ctx.client("athena")
    wg_name = ctx.unique_name("sim2real-behav-wg-")
    athena.create_work_group(
        Name=wg_name, Tags=[{"Key": "sim2real-behav", "Value": "true"}]
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name))

    stmt_name = ctx.unique_name("sim2real_behav_stmt_").replace("-", "_")
    athena.create_prepared_statement(
        StatementName=stmt_name,
        WorkGroup=wg_name,
        QueryStatement="SELECT 1",
        Description="original",
    )
    ctx.on_cleanup(
        lambda: athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup=wg_name)
    )

    created = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg_name)[
        "PreparedStatement"
    ]
    assert created["QueryStatement"] == "SELECT 1", created["QueryStatement"]
    assert created["Description"] == "original", created["Description"]

    # positive control: update against the real (existing) statement succeeds
    athena.update_prepared_statement(
        StatementName=stmt_name,
        WorkGroup=wg_name,
        QueryStatement="SELECT 2",
        Description="updated",
    )
    updated = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg_name)[
        "PreparedStatement"
    ]
    assert updated["QueryStatement"] == "SELECT 2", updated["QueryStatement"]
    assert updated["Description"] == "updated", updated["Description"]
    assert updated["StatementName"] == stmt_name, updated["StatementName"]
    assert updated["WorkGroupName"] == wg_name, updated["WorkGroupName"]

    # negative: a StatementName that was never created in this real WorkGroup is rejected
    missing_name = ctx.unique_name("sim2real_behav_missing_").replace("-", "_")
    got = _error(
        lambda: athena.update_prepared_statement(
            StatementName=missing_name, WorkGroup=wg_name, QueryStatement="SELECT 3"
        )
    )
    expected = (
        "ResourceNotFoundException",
        f"Prepared Statement {missing_name} does not exist in WorkGroup {wg_name} ",
    )
    assert got == expected, f"UpdatePreparedStatement on a missing name: expected {expected!r}, got {got!r}"

    # the rejected call did not create a statement under that missing name
    lookup = _error(
        lambda: athena.get_prepared_statement(StatementName=missing_name, WorkGroup=wg_name)
    )
    expected = (
        "ResourceNotFoundException",
        f"No Prepared Statement with statement name {missing_name} exists in WorkGroup {wg_name}",
    )
    assert lookup == expected, f"GetPreparedStatement on a missing name: expected {expected!r}, got {lookup!r}"

    # the real prepared statement is untouched by the failed call
    unaffected = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg_name)[
        "PreparedStatement"
    ]
    assert unaffected["QueryStatement"] == "SELECT 2", unaffected["QueryStatement"]


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
