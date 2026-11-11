"""op-contract-getPreparedStatement."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getPreparedStatement"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPreparedStatement returns the QueryStatement and Description given at creation, and rejects
    a StatementName with hyphens with InvalidRequestException and the exact pattern message."""
    athena = ctx.client("athena")

    wg = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=wg, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    stmt_name = ctx.unique_name("sim2real_athena_ps_")
    query_stmt = "SELECT 7 AS lucky"
    athena.create_prepared_statement(
        StatementName=stmt_name, WorkGroup=wg, QueryStatement=query_stmt,
        Description="sim2real behavioral prepared statement",
    )
    ctx.on_cleanup(lambda: athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup=wg))

    got = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg)["PreparedStatement"]
    assert got["StatementName"] == stmt_name, f"expected {stmt_name}, got {got['StatementName']}"
    assert got["QueryStatement"] == query_stmt, f"expected {query_stmt}, got {got['QueryStatement']}"
    assert got["WorkGroupName"] == wg, f"expected {wg}, got {got['WorkGroupName']}"
    assert got["Description"] == "sim2real behavioral prepared statement", (
        f"expected 'sim2real behavioral prepared statement', got {got['Description']}"
    )

    code, message = _error(
        lambda: athena.get_prepared_statement(StatementName="sim2real-missing-stmt", WorkGroup=wg)
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected = (
        "1 validation error detected: Value at 'statementName' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z_][a-zA-Z0-9_@:]{1,256}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
