"""op-contract-deletePreparedStatement."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deletePreparedStatement"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePreparedStatement removes the statement so a subsequent
    GetPreparedStatement fails, and deleting an already-deleted statement raises
    ResourceNotFoundException."""
    athena = ctx.client("athena")

    wg = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=wg)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    stmt_name = ctx.unique_name("sim2real_athena_ps_")
    athena.create_prepared_statement(StatementName=stmt_name, WorkGroup=wg, QueryStatement="SELECT 1")

    got = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg)["PreparedStatement"]
    assert got["StatementName"] == stmt_name, f"expected {stmt_name}, got {got['StatementName']}"

    athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup=wg)

    code, message = _error(lambda: athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"No Prepared Statement with statement name {stmt_name} exists in WorkGroup {wg}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Error boundary: deleting the same, now-nonexistent statement again is rejected.
    code2, message2 = _error(lambda: athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup=wg))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected2 = f"PreparedStatement {stmt_name} was not found in WorkGroup {wg}"
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
