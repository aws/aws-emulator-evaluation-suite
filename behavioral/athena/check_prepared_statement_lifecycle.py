"""prepared-statement-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "prepared-statement-lifecycle"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create/Get/Update/DeletePreparedStatement round-trip QueryStatement exactly; after delete, Get
    and Update raise ResourceNotFoundException, and the name is reusable with the new body."""
    athena = ctx.client("athena")
    stmt_name = ctx.unique_name("sim2real_athena_stmt_").replace("-", "_")
    athena.create_prepared_statement(
        StatementName=stmt_name,
        WorkGroup="primary",
        QueryStatement="SELECT ? AS x",
        Description="v1",
    )
    ctx.on_cleanup(
        lambda: athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup="primary")
    )

    got = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup="primary")[
        "PreparedStatement"
    ]
    assert got["StatementName"] == stmt_name, got["StatementName"]
    assert got["QueryStatement"] == "SELECT ? AS x", got["QueryStatement"]
    assert got["WorkGroupName"] == "primary", got["WorkGroupName"]
    assert got["Description"] == "v1", got["Description"]

    names = [
        p["StatementName"]
        for p in athena.list_prepared_statements(WorkGroup="primary")["PreparedStatements"]
    ]
    assert stmt_name in names, f"{stmt_name} missing from {names}"

    athena.update_prepared_statement(
        StatementName=stmt_name, WorkGroup="primary", QueryStatement="SELECT ? AS y"
    )
    got2 = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup="primary")[
        "PreparedStatement"
    ]
    assert got2["QueryStatement"] == "SELECT ? AS y", got2["QueryStatement"]

    athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup="primary")
    code, message = _error(
        lambda: athena.get_prepared_statement(StatementName=stmt_name, WorkGroup="primary")
    )
    assert code == "ResourceNotFoundException", code
    assert message == (
        f"No Prepared Statement with statement name {stmt_name} exists in WorkGroup primary"
    ), message

    update_code, update_message = _error(
        lambda: athena.update_prepared_statement(
            StatementName=stmt_name, WorkGroup="primary", QueryStatement="SELECT ? AS dead"
        )
    )
    assert update_code == "ResourceNotFoundException", update_code
    assert update_message == (
        f"Prepared Statement {stmt_name} does not exist in WorkGroup primary "
    ), update_message

    athena.create_prepared_statement(
        StatementName=stmt_name,
        WorkGroup="primary",
        QueryStatement="SELECT ? AS z",
        Description="v3",
    )
    got3 = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup="primary")[
        "PreparedStatement"
    ]
    assert got3["QueryStatement"] == "SELECT ? AS z", got3["QueryStatement"]
    assert got3["Description"] == "v3", got3["Description"]


def _error(fn):
    """The (code, message) of the ClientError `fn` raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected the call to raise a ClientError, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
