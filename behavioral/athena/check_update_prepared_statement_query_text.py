"""update-prepared-statement-query-text."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-prepared-statement-query-text"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePreparedStatement overwrites QueryStatement/Description for an existing statement and rejects an unknown name."""
    athena = ctx.client("athena")

    wg_name = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=wg_name, Tags=[{"Key": "sim2real", "Value": "update-prepared-statement-query-text"}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name))

    stmt_name = ctx.unique_name("sim2real_athena_stmt_")
    athena.create_prepared_statement(
        StatementName=stmt_name,
        WorkGroup=wg_name,
        QueryStatement="SELECT ? FROM foo",
        Description="v1",
    )
    ctx.on_cleanup(lambda: athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup=wg_name))

    fetched = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg_name)["PreparedStatement"]
    assert fetched["QueryStatement"] == "SELECT ? FROM foo", fetched["QueryStatement"]
    assert fetched["Description"] == "v1", fetched["Description"]

    # success path: change the parameterized SQL text and description in place.
    athena.update_prepared_statement(
        StatementName=stmt_name,
        WorkGroup=wg_name,
        QueryStatement="SELECT ? FROM bar WHERE x = ?",
        Description="v2",
    )
    updated = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg_name)["PreparedStatement"]
    assert updated["QueryStatement"] == "SELECT ? FROM bar WHERE x = ?", updated["QueryStatement"]
    assert updated["Description"] == "v2", updated["Description"]
    assert updated["StatementName"] == stmt_name, updated["StatementName"]
    assert updated["WorkGroupName"] == wg_name, updated["WorkGroupName"]

    # error boundary: updating a StatementName absent from this WorkGroup is rejected.
    missing_stmt = ctx.unique_name("sim2real_athena_missing_stmt_")
    code, message = _error(lambda: athena.update_prepared_statement(
        StatementName=missing_stmt, WorkGroup=wg_name, QueryStatement="SELECT 1"
    ))
    assert code == "ResourceNotFoundException", code
    assert message == f"Prepared Statement {missing_stmt} does not exist in WorkGroup {wg_name} ", message

    # positive control: the missing statement really was never created in this workgroup.
    names = {p["StatementName"] for p in athena.list_prepared_statements(WorkGroup=wg_name)["PreparedStatements"]}
    assert missing_stmt not in names, names
    assert stmt_name in names, names


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
