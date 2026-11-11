"""prepared-statement-delete-then-get-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "prepared-statement-delete-then-get-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeletePreparedStatement, GetPreparedStatement and UpdatePreparedStatement on the same
    name both raise ResourceNotFoundException; before the delete, Get returns the exact text."""
    athena = ctx.client("athena")
    wg_name = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=wg_name)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    stmt_name = ctx.unique_name("sim2real_stmt_").replace("-", "_")
    athena.create_prepared_statement(
        StatementName=stmt_name, WorkGroup=wg_name, QueryStatement="SELECT 1"
    )

    before = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg_name)["PreparedStatement"]
    assert before["QueryStatement"] == "SELECT 1", f"expected 'SELECT 1', got {before['QueryStatement']!r}"

    athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup=wg_name)

    got = _error(
        lambda: athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg_name)
    )
    expected = (
        "ResourceNotFoundException",
        f"No Prepared Statement with statement name {stmt_name} exists in WorkGroup {wg_name}",
    )
    assert got == expected, f"GetPreparedStatement after delete: expected {expected!r}, got {got!r}"

    update_got = _error(
        lambda: athena.update_prepared_statement(
            StatementName=stmt_name, WorkGroup=wg_name, QueryStatement="SELECT 2"
        )
    )
    expected = (
        "ResourceNotFoundException",
        f"Prepared Statement {stmt_name} does not exist in WorkGroup {wg_name} ",
    )
    assert update_got == expected, (
        f"UpdatePreparedStatement after delete: expected {expected!r}, got {update_got!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    instead: accepting a call AWS refuses is a distinct failure, not an error-code mismatch."""
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
