"""athena-prepared-statement-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "athena-prepared-statement-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePreparedStatement with a StatementName already used in the WorkGroup is rejected."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=wg, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    stmt_name = ctx.unique_name("sim2real-athena-ps-").replace("-", "_")
    athena.create_prepared_statement(
        StatementName=stmt_name, WorkGroup=wg, QueryStatement="SELECT 1", Description="original"
    )

    from botocore.exceptions import ClientError

    try:
        athena.create_prepared_statement(
            StatementName=stmt_name, WorkGroup=wg, QueryStatement="SELECT 2", Description="dup"
        )
        raise AssertionError("expected duplicate CreatePreparedStatement to raise InvalidRequestException")
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        expected = (
            "InvalidRequestException",
            f"Prepared Statement {stmt_name} already exists in WorkGroup {wg} ",
        )
        assert got == expected, (
            f"creating a prepared statement with a StatementName that already exists in the "
            f"WorkGroup: expected {expected!r}, got {got!r}"
        )

    # The forbidden effect did not happen: the original statement text is untouched.
    ps = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg)["PreparedStatement"]
    assert ps["QueryStatement"] == "SELECT 1", (
        f"rejected duplicate CreatePreparedStatement mutated QueryStatement: {ps['QueryStatement']!r}"
    )
    assert ps["Description"] == "original", (
        f"rejected duplicate CreatePreparedStatement mutated Description: {ps['Description']!r}"
    )

    # Positive control: a different name in the same workgroup succeeds.
    other_stmt = stmt_name + "_other"
    athena.create_prepared_statement(StatementName=other_stmt, WorkGroup=wg, QueryStatement="SELECT 3")
    other_query = athena.get_prepared_statement(StatementName=other_stmt, WorkGroup=wg)[
        "PreparedStatement"
    ]["QueryStatement"]
    assert other_query == "SELECT 3", f"expected control statement's QueryStatement 'SELECT 3', got {other_query!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
