"""sql-named-parameters-bind-and-mismatched-parameters-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sql-named-parameters-bind-and-mismatched-parameters-rejected"
GROUP = 'sql-parameters-rejected'
SERVICES = ['redshift-data']

# ===== helpers =====
# A redshift-data statement needs a workgroup, so the check provisions its own Redshift Serverless
# namespace + workgroup. The namespace is AVAILABLE synchronously, the workgroup reaches AVAILABLE in
# about a minute and deletes in up to ~3 minutes; 8 RPU is the smallest base capacity accepted.
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

    Raises AssertionError when fn() SUCCEEDS, so accepting input AWS rejects is not disguised as
    a code mismatch.
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
    # Built rather than written down so no credential-shaped literal is ever committed. The
    # namespace it authenticates is deleted by this check's own teardown; nothing here reaches it,
    # because redshift-data signs with the leased IAM identity, not this password.
    rss.create_namespace(
        namespaceName=namespace, adminUsername=_ADMIN_USER,
        adminUserPassword="Aa1" + ctx.unique_name("sim2real"), dbName=_DATABASE,
        tags=[{"key": "sim2real", "value": "true"}],
    )
    # Registered FIRST so LIFO runs it LAST, after the workgroup teardown below.
    ctx.on_cleanup(lambda: _delete_namespace(rss, namespace))
    rss.create_workgroup(
        workgroupName=workgroup, namespaceName=namespace,
        baseCapacity=_BASE_CAPACITY, publiclyAccessible=False,
        tags=[{"key": "sim2real", "value": "true"}],
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


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Named parameters are bound, not interpolated (a quoted value round-trips and an injection
    payload matches no rows), and every parameter-name mismatch is a synchronous 400
    ValidationException while a SQL error is delivered asynchronously as FAILED."""
    workgroup = _serverless_workgroup(ctx)
    rsd = ctx.client("redshift-data")
    table = ctx.unique_name("sim2real_behav_prm_")

    _must_finish(rsd, workgroup, f"create table {table}(id int, name varchar(32))")

    quoted = "o'brien"
    inserted = _must_finish(
        rsd, workgroup, f"insert into {table} values (:i, :n)",
        Parameters=[{"name": "i", "value": "1"}, {"name": "n", "value": quoted}],
    )
    assert inserted["QueryParameters"] == [
        {"name": "i", "value": "1"}, {"name": "n", "value": quoted}
    ], (
        f"DescribeStatement must echo the submitted parameters verbatim, got "
        f"{inserted.get('QueryParameters')!r}"
    )
    assert inserted["QueryString"] == f"insert into {table} values (:i, :n)", (
        f"QueryString must be the UNSUBSTITUTED sql, got {inserted.get('QueryString')!r}"
    )
    assert inserted["ResultRows"] == 1, (
        f"the parameterised insert must report 1 row, got {inserted.get('ResultRows')!r}"
    )

    read = _must_finish(
        rsd, workgroup, f"select id, name from {table} where name = :n",
        Parameters=[{"name": "n", "value": quoted}],
    )
    rows = rsd.get_statement_result(Id=read["Id"])["Records"]
    assert rows == [[{"longValue": 1}, {"stringValue": quoted}]], (
        f"the quote in the bound value must round-trip literally, got {rows!r}"
    )

    injected = _must_finish(
        rsd, workgroup, f"select id, name from {table} where name = :n",
        Parameters=[{"name": "n", "value": "' or 1=1 --"}],
    )
    assert injected["ResultRows"] == 0, (
        f"an injection payload must be BOUND as a literal and match nothing, but the statement "
        f"returned {injected.get('ResultRows')!r} rows — the parameter was interpolated"
    )
    assert rsd.get_statement_result(Id=injected["Id"])["Records"] == [], (
        "the injection statement must return no records at all"
    )

    select = f"select id from {table} where id = :i"
    missing = _rejection(
        lambda: rsd.execute_statement(
            WorkgroupName=workgroup, Database=_DATABASE, Sql=select,
            Parameters=[{"name": "zzz", "value": "1"}],
        )
    )
    assert missing[0] == "ValidationException", (
        f"a parameter the SQL does not name must be rejected ValidationException, got {missing[0]!r}"
    )
    assert missing[1] == 400, f"expected HTTP 400, got {missing[1]!r}"
    assert missing[2] == "Parameters list doesn't contain all parameters. Missing parameters: [i]", (
        f"unexpected missing-parameter message {missing[2]!r}"
    )

    unused = _rejection(
        lambda: rsd.execute_statement(
            WorkgroupName=workgroup, Database=_DATABASE, Sql=select,
            Parameters=[{"name": "i", "value": "1"}, {"name": "x", "value": "2"}],
        )
    )
    assert unused[0] == "ValidationException", (
        f"an extra parameter must be rejected ValidationException, got {unused[0]!r}"
    )
    assert unused[1] == 400, f"expected HTTP 400, got {unused[1]!r}"
    assert unused[2] == "Parameters list contains unused parameters. Unused parameters: [x]", (
        f"unexpected unused-parameter message {unused[2]!r}"
    )

    duplicate = _rejection(
        lambda: rsd.execute_statement(
            WorkgroupName=workgroup, Database=_DATABASE, Sql=select,
            Parameters=[{"name": "i", "value": "1"}, {"name": "i", "value": "2"}],
        )
    )
    assert duplicate[0] == "ValidationException", (
        f"a duplicate parameter name must be rejected ValidationException, got {duplicate[0]!r}"
    )
    assert duplicate[1] == 400, f"expected HTTP 400, got {duplicate[1]!r}"
    assert duplicate[2] == 'Found duplicate named parameter "i"', (
        f"unexpected duplicate-parameter message {duplicate[2]!r}"
    )

    # Effect absent: none of the three refusals registered a statement, so the table still holds
    # exactly the one row the accepted insert wrote.
    counted = _must_finish(rsd, workgroup, f"select count(*) as c from {table}")
    assert rsd.get_statement_result(Id=counted["Id"])["Records"] == [[{"longValue": 1}]], (
        "the refused submissions must not have written anything"
    )

    # Positive control in the same file: the same SQL with the RIGHT parameter is accepted.
    control = _must_finish(
        rsd, workgroup, select, Parameters=[{"name": "i", "value": "1"}]
    )
    assert rsd.get_statement_result(Id=control["Id"])["Records"] == [[{"longValue": 1}]], (
        "the control statement must return the inserted row"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
