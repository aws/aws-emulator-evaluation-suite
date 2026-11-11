"""prepared-statement-list-and-batch-get-partial."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "prepared-statement-list-and-batch-get-partial"
GROUP = 'prepared-statement'
SERVICES = ['athena']

def _list_all(athena, method_name, result_key, **kwargs):
    method = getattr(athena, method_name)
    items = []
    token = None
    while True:
        call = dict(kwargs)
        if token:
            call["NextToken"] = token
        resp = method(**call)
        items.extend(resp.get(result_key, []))
        token = resp.get("NextToken")
        if not token:
            return items

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPreparedStatements + BatchGetPreparedStatement report unknown names as unprocessed
    with the specific STATEMENT_NOT_FOUND error code, while known names come back with their
    full body intact."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-behav-wg-")
    athena.create_work_group(Name=wg, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    stmt_name = ctx.unique_name("sim2real-behav-stmt_").replace("-", "_")
    query_statement = "SELECT 1"
    athena.create_prepared_statement(
        StatementName=stmt_name, WorkGroup=wg, QueryStatement=query_statement
    )
    ctx.on_cleanup(lambda: athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup=wg))

    listed_names = {
        s["StatementName"]
        for s in _list_all(athena, "list_prepared_statements", "PreparedStatements", WorkGroup=wg)
    }
    assert stmt_name in listed_names, f"expected {stmt_name!r} in ListPreparedStatements, got {listed_names}"

    bogus_name = ctx.unique_name("sim2real-behav-missing_stmt_").replace("-", "_")
    resp = athena.batch_get_prepared_statement(
        PreparedStatementNames=[stmt_name, bogus_name], WorkGroup=wg
    )
    found = {s["StatementName"]: s for s in resp["PreparedStatements"]}
    unprocessed = {u["StatementName"]: u for u in resp["UnprocessedPreparedStatementNames"]}

    assert stmt_name in found, f"expected {stmt_name!r} in PreparedStatements, got {list(found)}"
    assert found[stmt_name]["QueryStatement"] == query_statement, (
        f"expected QueryStatement {query_statement!r}, got {found[stmt_name]['QueryStatement']!r}"
    )
    assert bogus_name not in found, f"unknown name {bogus_name!r} must not appear in PreparedStatements"
    assert bogus_name in unprocessed, f"expected {bogus_name!r} in UnprocessedPreparedStatementNames, got {list(unprocessed)}"
    assert unprocessed[bogus_name].get("ErrorCode") == "STATEMENTNAME_NOT_FOUND", (
        f"expected ErrorCode STATEMENTNAME_NOT_FOUND for unknown name, got {unprocessed[bogus_name].get('ErrorCode')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
