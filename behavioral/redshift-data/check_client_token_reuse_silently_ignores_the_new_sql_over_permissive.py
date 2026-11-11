"""client-token-reuse-silently-ignores-the-new-sql-over-permissive."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "client-token-reuse-silently-ignores-the-new-sql-over-permissive"
GROUP = 'client-token-over-permissive'
SERVICES = ['redshift-data']

# ===== helpers =====
# Every check in this suite provisions its OWN Redshift Serverless namespace + workgroup, because a
# redshift-data statement cannot run without one and checks share no state.
# The namespace is AVAILABLE synchronously, the workgroup reaches AVAILABLE in about a minute,
# and delete_workgroup takes a few minutes. 8 RPU is the
# smallest base capacity the service accepts, and Serverless bills RPU-seconds only while the
# workgroup is processing, so an idle 8-RPU workgroup for two minutes is the cheapest shape that
# can run SQL at all.
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
    """Poll fn() until predicate holds; never a bare sleep standing in for the wait."""
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
    # because redshift-data signs with the caller's IAM identity, not this password.
    rss.create_namespace(
        namespaceName=namespace, adminUsername=_ADMIN_USER,
        adminUserPassword="Aa1" + ctx.unique_name("sim2real"), dbName=_DATABASE,
        tags=[{"key": "sim2real:managed", "value": "true"}],
    )
    # Registered FIRST so LIFO runs it LAST, after the workgroup teardown below.
    ctx.on_cleanup(lambda: _delete_namespace(rss, namespace))
    rss.create_workgroup(
        workgroupName=workgroup, namespaceName=namespace,
        baseCapacity=_BASE_CAPACITY, publiclyAccessible=False,
        tags=[{"key": "sim2real:managed", "value": "true"}],
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


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A reused ClientToken returns the first statement's Id with no error, overwrites the record's
    QueryString with the new SQL, and runs nothing: the table holds only the first SQL's row.
    """
    workgroup = _serverless_workgroup(ctx)
    rsd = ctx.client("redshift-data")
    table = ctx.unique_name("sim2real_behav_tok_")

    _must_finish(rsd, workgroup, f"create table {table}(label varchar(16))")

    token = ctx.unique_name("sim2real-behav-rsd-tok-")
    first_sql = f"insert into {table} values ('first')"
    second_sql = f"insert into {table} values ('second')"

    first = rsd.execute_statement(
        WorkgroupName=workgroup, Database=_DATABASE, Sql=first_sql, ClientToken=token
    )
    original = _poll(
        lambda: rsd.describe_statement(Id=first["Id"]),
        lambda d: d["Status"] in _TERMINAL,
        f"statement {first['Id']} reaching a terminal state",
        timeout_s=_STATEMENT_DEADLINE_S, interval_s=_STATEMENT_POLL_S,
    )
    assert original["Status"] == "FINISHED", (
        f"the first insert must FINISH before the token is reused, got {original['Status']!r}"
    )
    assert original["QueryString"] == first_sql, (
        f"the record must start out reporting the sql that ran, got "
        f"{original.get('QueryString')!r}"
    )
    assert original["ResultRows"] == 1, (
        f"the first insert must report 1 row, got {original.get('ResultRows')!r}"
    )

    replay = rsd.execute_statement(
        WorkgroupName=workgroup, Database=_DATABASE, Sql=first_sql, ClientToken=token
    )
    assert replay["Id"] == first["Id"], (
        f"an identical resubmission under the same token must return the same Id: first "
        f"{first['Id']!r}, replay {replay['Id']!r}"
    )

    mismatched = rsd.execute_statement(
        WorkgroupName=workgroup, Database=_DATABASE, Sql=second_sql, ClientToken=token
    )
    assert mismatched["Id"] == first["Id"], (
        f"reusing the token with DIFFERENT sql must return the FIRST statement's Id rather than "
        f"rejecting the mismatch; got {mismatched['Id']!r} against {first['Id']!r}"
    )

    rewritten = rsd.describe_statement(Id=mismatched["Id"])
    assert rewritten["QueryString"] == second_sql, (
        f"the record must now MISREPORT itself as the newly submitted sql; got "
        f"{rewritten.get('QueryString')!r}"
    )
    assert rewritten["Status"] == "FINISHED", (
        f"and it must still be the FIRST execution's terminal status, got {rewritten['Status']!r}"
    )
    assert rewritten["CreatedAt"] == original["CreatedAt"], (
        f"CreatedAt must be frozen at the first execution: was {original['CreatedAt']!r}, now "
        f"{rewritten['CreatedAt']!r}"
    )
    assert rewritten["UpdatedAt"] == original["UpdatedAt"], (
        f"UpdatedAt must be frozen too — nothing ran: was {original['UpdatedAt']!r}, now "
        f"{rewritten['UpdatedAt']!r}"
    )
    assert rewritten["ResultRows"] == original["ResultRows"], (
        f"ResultRows must be frozen at the first execution's {original['ResultRows']!r}, got "
        f"{rewritten['ResultRows']!r}"
    )

    # Effect absent: the rewritten sql never wrote its row, so the record and the database disagree.
    counted = _must_finish(rsd, workgroup, f"select label from {table} order by label")
    rows = rsd.get_statement_result(Id=counted["Id"])["Records"]
    assert rows == [[{"stringValue": "first"}]], (
        f"only the FIRST statement's row may exist — three submissions under one token wrote once, "
        f"and the sql the record now reports never ran; got {rows!r}"
    )

    # Positive control in the same file: a FRESH token runs the very same second_sql.
    fresh_token = ctx.unique_name("sim2real-behav-rsd-tok2-")
    fresh = rsd.execute_statement(
        WorkgroupName=workgroup, Database=_DATABASE, Sql=second_sql, ClientToken=fresh_token
    )
    assert fresh["Id"] != first["Id"], (
        f"a fresh token must mint a new statement, got {fresh['Id']!r} again"
    )
    control = _poll(
        lambda: rsd.describe_statement(Id=fresh["Id"]),
        lambda d: d["Status"] in _TERMINAL,
        f"statement {fresh['Id']} reaching a terminal state",
        timeout_s=_STATEMENT_DEADLINE_S, interval_s=_STATEMENT_POLL_S,
    )
    assert control["Status"] == "FINISHED", (
        f"the control insert must FINISH, got {control['Status']!r} / {control.get('Error')!r}"
    )
    final = _must_finish(rsd, workgroup, f"select label from {table} order by label")
    assert rsd.get_statement_result(Id=final["Id"])["Records"] == [
        [{"stringValue": "first"}], [{"stringValue": "second"}]
    ], "with a fresh token the same sql DOES write, so the absence above was the token's doing"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
