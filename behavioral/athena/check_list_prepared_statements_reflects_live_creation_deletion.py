"""list-prepared-statements-reflects-live-creation-deletion."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-prepared-statements-reflects-live-creation-deletion"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPreparedStatements is a live view that includes a prepared statement
    immediately after CreatePreparedStatement and excludes it immediately after
    DeletePreparedStatement."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-behav-wg-")
    athena.create_work_group(Name=wg, Tags=[{"Key": "sim2real", "Value": "list-prepared-statements-reflects-live"}])
    ctx.on_cleanup(lambda: _safe_delete_workgroup(athena, wg))

    # StatementName does not accept hyphens (only alphanumeric/underscore); ctx.unique_name's
    # default hyphenated form is rejected server-side with an InvalidRequestException.
    stmt_name = ctx.unique_name("sim2real_behav_stmt_").replace("-", "_")
    before_names = set(_prepared_statement_names(athena, wg))
    assert stmt_name not in before_names, f"unique name {stmt_name!r} already present before creation: {before_names}"

    athena.create_prepared_statement(StatementName=stmt_name, WorkGroup=wg, QueryStatement="SELECT 1")
    ctx.on_cleanup(lambda: _safe_delete_statement(athena, stmt_name, wg))

    after_create_names = set(_prepared_statement_names(athena, wg))
    assert stmt_name in after_create_names, "prepared statement missing immediately after creation"

    fetched = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg)["PreparedStatement"]
    assert fetched["QueryStatement"] == "SELECT 1", fetched["QueryStatement"]

    athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup=wg)
    after_delete_names = set(_prepared_statement_names(athena, wg))
    assert stmt_name not in after_delete_names, "deleted prepared statement still listed"


def _prepared_statement_names(athena, workgroup):
    out = []
    token = None
    while True:
        kwargs = {"WorkGroup": workgroup}
        if token:
            kwargs["NextToken"] = token
        resp = athena.list_prepared_statements(**kwargs)
        out.extend(s["StatementName"] for s in resp["PreparedStatements"])
        token = resp.get("NextToken")
        if not token:
            break
    return out


def _safe_delete_statement(athena, stmt_name, workgroup):
    try:
        athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup=workgroup)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_workgroup(athena, workgroup):
    try:
        athena.delete_work_group(WorkGroup=workgroup, RecursiveDeleteOption=True)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err.get("Code") == "InvalidRequestException" and "not found" in err.get("Message", "")):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
