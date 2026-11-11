"""athena-prepared-statement-crud-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "athena-prepared-statement-crud-lifecycle"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePreparedStatement -> UpdatePreparedStatement mutates QueryStatement -> Delete removes it."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=wg, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    stmt_name = ctx.unique_name("sim2real-athena-ps-").replace("-", "_")

    athena.create_prepared_statement(
        StatementName=stmt_name,
        WorkGroup=wg,
        QueryStatement="SELECT 1",
        Description="v1",
    )

    ps = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg)["PreparedStatement"]
    assert ps["StatementName"] == stmt_name, f"expected StatementName {stmt_name!r}, got {ps['StatementName']!r}"
    assert ps["QueryStatement"] == "SELECT 1", f"expected QueryStatement 'SELECT 1', got {ps['QueryStatement']!r}"
    assert ps["WorkGroupName"] == wg, f"expected WorkGroupName {wg!r}, got {ps['WorkGroupName']!r}"
    assert ps["Description"] == "v1", f"expected Description 'v1', got {ps['Description']!r}"

    athena.update_prepared_statement(
        StatementName=stmt_name, WorkGroup=wg, QueryStatement="SELECT 2", Description="v2"
    )
    ps2 = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg)["PreparedStatement"]
    assert ps2["QueryStatement"] == "SELECT 2", f"expected updated QueryStatement 'SELECT 2', got {ps2['QueryStatement']!r}"
    assert ps2["Description"] == "v2", f"expected updated Description 'v2', got {ps2['Description']!r}"

    names = [p["StatementName"] for p in athena.list_prepared_statements(WorkGroup=wg)["PreparedStatements"]]
    assert stmt_name in names, f"expected {stmt_name!r} in ListPreparedStatements, got {names!r}"

    athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup=wg)

    from botocore.exceptions import ClientError

    try:
        athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg)
        raise AssertionError("expected GetPreparedStatement on a deleted statement to raise")
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        expected = (
            "ResourceNotFoundException",
            f"No Prepared Statement with statement name {stmt_name} exists in WorkGroup {wg}",
        )
        assert got == expected, f"GetPreparedStatement after delete: expected {expected!r}, got {got!r}"

    try:
        athena.update_prepared_statement(StatementName=stmt_name, WorkGroup=wg, QueryStatement="SELECT 3")
        raise AssertionError("expected UpdatePreparedStatement on a deleted statement to raise")
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        expected = (
            "ResourceNotFoundException",
            f"Prepared Statement {stmt_name} does not exist in WorkGroup {wg} ",
        )
        assert got == expected, f"UpdatePreparedStatement after delete: expected {expected!r}, got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
