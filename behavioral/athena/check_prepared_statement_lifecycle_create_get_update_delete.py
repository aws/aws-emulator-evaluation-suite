"""prepared-statement-lifecycle-create-get-update-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "prepared-statement-lifecycle-create-get-update-delete"
GROUP = 'prepared-statement'
SERVICES = ['athena']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PreparedStatement supports create -> get -> update -> delete scoped to its WorkGroup,
    and once deleted the statement is both unreadable and unmutable by the same name."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-behav-wg-")
    athena.create_work_group(
        Name=wg,
        Tags=[{"Key": "sim2real", "Value": "prepared-statement-lifecycle-create-get-update-delete"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    stmt_name = ctx.unique_name("sim2real-behav-stmt_").replace("-", "_")
    athena.create_prepared_statement(
        StatementName=stmt_name,
        WorkGroup=wg,
        QueryStatement="SELECT ? AS col",
        Description="v1",
    )
    ctx.on_cleanup(lambda: _delete_statement_if_present(athena, stmt_name, wg))

    got = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg)["PreparedStatement"]
    assert got["StatementName"] == stmt_name, f"expected StatementName {stmt_name!r}, got {got!r}"
    assert got["QueryStatement"] == "SELECT ? AS col", f"expected v1 QueryStatement, got {got!r}"
    assert got["WorkGroupName"] == wg, f"expected WorkGroupName {wg!r}, got {got!r}"
    assert got["Description"] == "v1", f"expected v1 Description, got {got!r}"

    athena.update_prepared_statement(
        StatementName=stmt_name,
        WorkGroup=wg,
        QueryStatement="SELECT ? AS col2",
        Description="v2",
    )
    updated = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg)["PreparedStatement"]
    assert updated["QueryStatement"] == "SELECT ? AS col2", f"update not reflected, got {updated!r}"
    assert updated["Description"] == "v2", f"update not reflected, got {updated!r}"

    athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup=wg)

    code, message = _error(lambda: athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == (
        f"No Prepared Statement with statement name {stmt_name} exists in WorkGroup {wg}"
    ), f"unexpected GetPreparedStatement message: {message!r}"

    mutate_code, mutate_message = _error(
        lambda: athena.update_prepared_statement(
            StatementName=stmt_name, WorkGroup=wg, QueryStatement="SELECT ? AS col3"
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected UpdatePreparedStatement on a deleted statement to raise "
        f"ResourceNotFoundException, got {mutate_code}"
    )
    assert mutate_message == f"Prepared Statement {stmt_name} does not exist in WorkGroup {wg} ", (
        f"unexpected UpdatePreparedStatement message: {mutate_message!r}"
    )


def _error(fn):
    """The (code, message) of the ClientError `fn` raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to raise, but it succeeded")


def _delete_statement_if_present(athena, stmt_name, wg):
    """Teardown for a statement the body deletes on the success path."""
    from botocore.exceptions import ClientError

    try:
        athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup=wg)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
