"""prepared-statement-get-nonexistent-resource-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "prepared-statement-get-nonexistent-resource-not-found"
GROUP = 'error-semantics'
SERVICES = ['athena']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPreparedStatement on an unknown name raises ResourceNotFoundException, not
    InvalidRequestException, while a statement created in the same workgroup reads back."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-behav-wg-")
    athena.create_work_group(Name=wg, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    real_stmt_name = ctx.unique_name("sim2real-behav-real_stmt_").replace("-", "_")
    athena.create_prepared_statement(
        StatementName=real_stmt_name, WorkGroup=wg, QueryStatement="SELECT 1"
    )
    ctx.on_cleanup(
        lambda: athena.delete_prepared_statement(StatementName=real_stmt_name, WorkGroup=wg)
    )
    positive = athena.get_prepared_statement(StatementName=real_stmt_name, WorkGroup=wg)
    got_name = positive["PreparedStatement"].get("StatementName")
    assert got_name == real_stmt_name, f"positive control: expected {real_stmt_name}, got {got_name}"

    stmt_name = ctx.unique_name("sim2real-behav-no_such_stmt_").replace("-", "_")
    from botocore.exceptions import ClientError

    try:
        result = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg)
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    else:
        raise AssertionError(f"expected GetPreparedStatement on an unknown name to fail, got {result!r}")
    expected = (
        "ResourceNotFoundException",
        f"No Prepared Statement with statement name {stmt_name} exists in WorkGroup {wg}",
    )
    assert got == expected, f"expected {expected!r}, got {got!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
