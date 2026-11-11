"""cancel-running-statement-aborts-and-terminal-cancel-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-running-statement-aborts-and-terminal-cancel-rejected"
GROUP = 'cancel-rejected'
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
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    # Registered FIRST so LIFO runs it LAST, after the workgroup teardown below.
    ctx.on_cleanup(lambda: _delete_namespace(rss, namespace))
    rss.create_workgroup(
        workgroupName=workgroup, namespaceName=namespace,
        baseCapacity=_BASE_CAPACITY, publiclyAccessible=False,
        tags=[{"key": "sim2real", "value": CHECK}],
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
    """CancelStatement aborts a STARTED statement (it lands ABORTED), and a second cancel of that
    id, or a cancel of a FINISHED statement, is a 400 ValidationException naming the terminal state;
    GetStatementResult on the aborted id is ResourceNotFoundException with a "does not have result" message."""
    workgroup = _serverless_workgroup(ctx)
    rsd = ctx.client("redshift-data")
    table = ctx.unique_name("sim2real_behav_can_")

    _must_finish(rsd, workgroup, f"create table {table}(i int)")
    _must_finish(
        rsd, workgroup,
        f"insert into {table} values (1),(2),(3),(4),(5),(6),(7),(8),(9),(10)",
    )
    for _ in range(6):
        _must_finish(rsd, workgroup, f"insert into {table} select i from {table}")
    counted = _must_finish(rsd, workgroup, f"select count(*) as c from {table}")
    assert rsd.get_statement_result(Id=counted["Id"])["Records"] == [[{"longValue": 640}]], (
        "the row-doubling setup must leave exactly 640 rows for the long query below"
    )

    long_running = rsd.execute_statement(
        WorkgroupName=workgroup, Database=_DATABASE,
        Sql=f"select count(*) from {table} a, {table} b, {table} c, {table} d, {table} e",
    )
    statement_id = long_running["Id"]
    _poll(
        lambda: rsd.describe_statement(Id=statement_id)["Status"],
        lambda s: s in ("STARTED",) + _TERMINAL,
        f"statement {statement_id} leaving SUBMITTED",
        timeout_s=_STATEMENT_DEADLINE_S, interval_s=_STATEMENT_POLL_S,
    )
    running = rsd.describe_statement(Id=statement_id)
    assert running["Status"] == "STARTED", (
        f"the 640^5-row query must still be running when the cancel is issued, but it was "
        f"{running['Status']!r} — the cancel below would not be mid-flight"
    )

    cancelled = rsd.cancel_statement(Id=statement_id)
    assert cancelled["Status"] is True, (
        f"CancelStatement on a running statement must answer Status true, got "
        f"{cancelled.get('Status')!r}"
    )

    aborted = _poll(
        lambda: rsd.describe_statement(Id=statement_id),
        lambda d: d["Status"] in _TERMINAL,
        f"statement {statement_id} reaching a terminal state after the cancel",
        timeout_s=_STATEMENT_DEADLINE_S, interval_s=_STATEMENT_POLL_S,
    )
    assert aborted["Status"] == "ABORTED", (
        f"a cancelled statement must land ABORTED, not FINISHED or FAILED; got "
        f"{aborted['Status']!r} / {aborted.get('Error')!r}"
    )
    # The query id inside the message is server-minted, so the stable part is the suffix.
    assert aborted.get("Error", "").endswith("cancelled on user's request"), (
        f"the aborted statement must carry the engine's own cancellation message, got "
        f"{aborted.get('Error')!r}"
    )
    assert aborted.get("HasResultSet") in (None, False), (
        f"an aborted statement must not claim a result set, got {aborted.get('HasResultSet')!r}"
    )

    no_result = _rejection(lambda: rsd.get_statement_result(Id=statement_id))
    assert no_result[0] == "ResourceNotFoundException", (
        f"reading an aborted statement's result must be rejected ResourceNotFoundException, got "
        f"{no_result[0]!r}"
    )
    assert no_result[1] == 400, (
        f"ResourceNotFoundException here is an HTTP 400, not a 404, got {no_result[1]!r}"
    )
    assert no_result[2] == (
        "Query does not have result. Please check query status with DescribeStatement."
    ), f"unexpected no-result message {no_result[2]!r}"

    again = _rejection(lambda: rsd.cancel_statement(Id=statement_id))
    assert again[0] == "ValidationException", (
        f"cancelling an already-aborted statement must be rejected ValidationException, got "
        f"{again[0]!r}"
    )
    assert again[1] == 400, f"expected HTTP 400, got {again[1]!r}"
    assert again[2] == (
        f"Could not cancel a query that is already in ABORTED state with ID: {statement_id}"
    ), f"unexpected double-cancel message {again[2]!r}"

    # Positive control in the same file: a statement left alone FINISHES, and cancelling THAT is
    # refused with the same sentence naming FINISHED instead — so the refusal is about state, not
    # about the id being spent.
    finished = _must_finish(rsd, workgroup, f"select count(*) as c from {table}")
    assert rsd.get_statement_result(Id=finished["Id"])["Records"] == [[{"longValue": 640}]], (
        "the control statement must return the row count"
    )
    late = _rejection(lambda: rsd.cancel_statement(Id=finished["Id"]))
    assert late[0] == "ValidationException", (
        f"cancelling a FINISHED statement must be rejected ValidationException, got {late[0]!r}"
    )
    assert late[1] == 400, f"expected HTTP 400, got {late[1]!r}"
    assert late[2] == (
        f"Could not cancel a query that is already in FINISHED state with ID: {finished['Id']}"
    ), f"unexpected late-cancel message {late[2]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
