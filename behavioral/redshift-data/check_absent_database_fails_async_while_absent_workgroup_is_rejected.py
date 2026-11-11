"""absent-database-fails-async-while-absent-workgroup-is-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "absent-database-fails-async-while-absent-workgroup-is-rejected"
GROUP = 'target-resolution-rejected'
SERVICES = ['redshift-data']

# A redshift-data statement needs a workgroup, so the check provisions its own. The workgroup
# reaches AVAILABLE in about a minute and deletes in up to ~3 minutes; 8 RPU is the smallest base
# capacity the service accepts.
_WORKGROUP_DEADLINE_S = 600.0
_WORKGROUP_POLL_S = 5.0
_STATEMENT_DEADLINE_S = 240.0
_STATEMENT_POLL_S = 0.5
_ADMIN_USER = "adminuser"
_DATABASE = "devdb"
_BASE_CAPACITY = 8
_TERMINAL = ("FINISHED", "FAILED", "ABORTED")


def _rejection(fn):
    """(error code, HTTP status, message) of the ClientError fn() raises.

    A call that succeeds raises AssertionError, so it cannot read as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (
            err.get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            err.get("Message"),
        )
    raise AssertionError(f"expected a rejection but the call SUCCEEDED, returning {result!r}")


def _poll(fn, predicate, what, timeout_s, interval_s):
    """Poll fn() until predicate holds or timeout_s elapses."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = fn()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed {last!r}"
            )
        time.sleep(interval_s)


def _delete_workgroup(rss, workgroup):
    """Undo create_workgroup, and WAIT: base capacity is billed while the workgroup exists, and
    delete_namespace is refused until it is gone. ConflictException (still CREATING/MODIFYING) is
    retried; the delete and the wait share one deadline."""
    deadline = time.monotonic() + _WORKGROUP_DEADLINE_S
    while True:
        try:
            rss.delete_workgroup(workgroupName=workgroup)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    _poll(
        lambda: _workgroup_gone(rss, workgroup),
        bool, f"workgroup {workgroup} deleted",
        timeout_s=max(0.0, deadline - time.monotonic()), interval_s=2,
    )


def _workgroup_gone(rss, workgroup):
    try:
        rss.get_workgroup(workgroupName=workgroup)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return True
        raise
    return False


def _delete_namespace(rss, namespace):
    """Undo create_namespace, retrying while the workgroup teardown above is still in flight (the
    namespace cannot be deleted until no workgroup references it). Bounded so both teardowns
    fit the suite's cleanup budget."""
    deadline = time.monotonic() + 120.0
    while True:
        try:
            rss.delete_namespace(namespaceName=namespace)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _serverless_workgroup(ctx):
    """Provision the cheapest Redshift Serverless namespace + workgroup and return the name."""
    rss = ctx.client("redshift-serverless")
    namespace = ctx.unique_name("sim2real-behav-rsd-ns-")
    workgroup = ctx.unique_name("sim2real-behav-rsd-wg-")
    # Password is built, not a literal; redshift-data authenticates with IAM, not this password.
    tags = [{"key": "sim2real:managed", "value": "true"}]
    rss.create_namespace(
        namespaceName=namespace, adminUsername=_ADMIN_USER,
        adminUserPassword="Aa1" + ctx.unique_name("sim2real"), dbName=_DATABASE,
        tags=tags,
    )
    # Registered FIRST so LIFO runs it LAST, after the workgroup teardown below.
    ctx.on_cleanup(lambda: _delete_namespace(rss, namespace))
    rss.create_workgroup(
        workgroupName=workgroup, namespaceName=namespace,
        baseCapacity=_BASE_CAPACITY, publiclyAccessible=False, tags=tags,
        subnetIds=ctx.network().subnet_ids,
    )
    ctx.on_cleanup(lambda: _delete_workgroup(rss, workgroup))
    _poll(
        lambda: rss.get_workgroup(workgroupName=workgroup)["workgroup"]["status"],
        lambda s: s == "AVAILABLE", f"workgroup {workgroup} reaching AVAILABLE",
        timeout_s=_WORKGROUP_DEADLINE_S, interval_s=_WORKGROUP_POLL_S,
    )
    return workgroup


def _run_sql(rsd, workgroup, sql, **kwargs):
    """Submit sql and poll DescribeStatement to a terminal state; return that DescribeStatement."""
    started = rsd.execute_statement(
        WorkgroupName=workgroup, Database=_DATABASE, Sql=sql, **kwargs
    )
    return _poll(
        lambda: rsd.describe_statement(Id=started["Id"]),
        lambda d: d["Status"] in _TERMINAL,
        f"statement {started['Id']} reaching a terminal state",
        timeout_s=_STATEMENT_DEADLINE_S, interval_s=_STATEMENT_POLL_S,
    )


def _must_finish(rsd, workgroup, sql, **kwargs):
    """_run_sql, asserting the statement FINISHED — setup SQL that fails is a check bug."""
    described = _run_sql(rsd, workgroup, sql, **kwargs)
    assert described["Status"] == "FINISHED", (
        f"setup SQL {sql!r} did not FINISH: {described['Status']!r} / {described.get('Error')!r}"
    )
    return described


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A nonexistent database is accepted with an Id and later FAILS asynchronously; a nonexistent
    workgroup is a synchronous 400 ValidationException on Execute, BatchExecute and ListDatabases
    that registers no statement.
    """
    workgroup = _serverless_workgroup(ctx)
    rsd = ctx.client("redshift-data")

    # Positive control in the same file: the live workgroup and its own database work.
    control = _must_finish(rsd, workgroup, "select 1 as ok")
    assert rsd.get_statement_result(Id=control["Id"])["Records"] == [[{"longValue": 1}]], (
        "the control statement must return its row"
    )
    assert control["WorkgroupName"] == workgroup, (
        f"DescribeStatement must report the workgroup it ran on, got "
        f"{control.get('WorkgroupName')!r}"
    )
    assert control["Database"] == _DATABASE, (
        f"DescribeStatement must report the database, got {control.get('Database')!r}"
    )

    absent_database = ctx.unique_name("sim2real_behav_nodb_")
    accepted = rsd.execute_statement(
        WorkgroupName=workgroup, Database=absent_database, Sql="select 1 as ok"
    )
    assert accepted["Id"], (
        f"a nonexistent database must still be ACCEPTED with an Id, got {accepted!r}"
    )
    assert accepted["Database"] == absent_database, (
        f"the submit response must echo the nonexistent database, got "
        f"{accepted.get('Database')!r}"
    )
    failed = _poll(
        lambda: rsd.describe_statement(Id=accepted["Id"]),
        lambda d: d["Status"] in _TERMINAL,
        f"statement {accepted['Id']} reaching a terminal state",
        timeout_s=_STATEMENT_DEADLINE_S, interval_s=_STATEMENT_POLL_S,
    )
    assert failed["Status"] == "FAILED", (
        f"a nonexistent database must surface ASYNCHRONOUSLY as FAILED, got {failed['Status']!r}"
    )
    assert failed.get("Error") == f'FATAL: database "{absent_database}" does not exist', (
        f"the failure must carry the engine's own message naming the database, got "
        f"{failed.get('Error')!r}"
    )
    result_of_failed = _rejection(lambda: rsd.get_statement_result(Id=accepted["Id"]))
    assert result_of_failed[0] == "ResourceNotFoundException", (
        f"a FAILED statement has no result to read, got {result_of_failed[0]!r}"
    )
    assert result_of_failed[2] == (
        "Query does not have result. Please check query status with DescribeStatement."
    ), f"unexpected no-result message {result_of_failed[2]!r}"

    absent_workgroup = ctx.unique_name("sim2real-behav-rsd-nowg-")
    endpoint_message = "Redshift endpoint doesn't exist in this region."
    # Named submissions keep the ListStatements absence check scoped to this scenario.
    refused_name = ctx.unique_name("sim2real-behav-rsd-refused-")
    accepted_name = ctx.unique_name("sim2real-behav-rsd-accepted-")

    execute = _rejection(
        lambda: rsd.execute_statement(
            WorkgroupName=absent_workgroup, Database=_DATABASE, Sql="select 1 as ok",
            StatementName=refused_name,
        )
    )
    assert execute[0] == "ValidationException", (
        f"a nonexistent workgroup must be rejected SYNCHRONOUSLY as ValidationException, not the "
        f"ResourceNotFoundException the operation declares; got {execute[0]!r}"
    )
    assert execute[1] == 400, f"expected HTTP 400, got {execute[1]!r}"
    assert execute[2] == endpoint_message, (
        f"unexpected absent-workgroup message {execute[2]!r}"
    )

    batch = _rejection(
        lambda: rsd.batch_execute_statement(
            WorkgroupName=absent_workgroup, Database=_DATABASE, Sqls=["select 1 as ok"],
            StatementName=refused_name,
        )
    )
    assert batch[0] == "ValidationException", (
        f"BatchExecuteStatement must reject the absent workgroup the same way, got {batch[0]!r}"
    )
    assert batch[1] == 400, f"expected HTTP 400, got {batch[1]!r}"
    assert batch[2] == endpoint_message, f"unexpected batch message {batch[2]!r}"

    catalogue = _rejection(
        lambda: rsd.list_databases(WorkgroupName=absent_workgroup, Database=_DATABASE)
    )
    assert catalogue[0] == "ValidationException", (
        f"ListDatabases must reject the absent workgroup the same way, got {catalogue[0]!r}"
    )
    assert catalogue[1] == 400, f"expected HTTP 400, got {catalogue[1]!r}"
    assert catalogue[2] == endpoint_message, f"unexpected catalogue message {catalogue[2]!r}"

    # ListStatements is eventually consistent: wait until it shows an accepted sibling before
    # asserting the refused name is absent, so an empty read is not just lag.
    _must_finish(rsd, workgroup, "select 2 as ok", StatementName=accepted_name)
    warm = _poll(
        lambda: rsd.list_statements(StatementName=accepted_name).get("Statements", []),
        lambda ss: len(ss) == 1,
        f"ListStatements to see the accepted statement named {accepted_name}",
        timeout_s=_STATEMENT_DEADLINE_S, interval_s=_STATEMENT_POLL_S,
    )
    assert warm[0]["StatementName"] == accepted_name, (
        f"ListStatements must echo StatementName, got {warm[0]!r}"
    )
    assert warm[0]["Status"] == "FINISHED", (
        f"the warm-up statement must be FINISHED, got {warm[0]['Status']!r}"
    )
    assert rsd.list_statements(StatementName=refused_name).get("Statements", []) == [], (
        f"the two SYNCHRONOUSLY refused submissions must have registered NO statement under "
        f"{refused_name!r}, but ListStatements returned "
        f"{rsd.list_statements(StatementName=refused_name).get('Statements')!r}"
    )
    # ...while the ASYNCHRONOUSLY failed one DID register: DescribeStatement still resolves its Id.
    assert rsd.describe_statement(Id=accepted["Id"])["Status"] == "FAILED", (
        "the bad-database statement must remain resolvable by Id — that is the difference between "
        "an accepted-then-failed statement and a refused submission"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
