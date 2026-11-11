"""catalogue-reflects-created-table-and-absent-table-over-permissive."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "catalogue-reflects-created-table-and-absent-table-over-permissive"
GROUP = 'catalogue-over-permissive'
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


@tags("axis:happy-path", "cap:c2", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The catalogue reads follow a table's life (it appears in ListTables/DescribeTable after CREATE
    and disappears after DROP), and none of them 404s once it is gone: DescribeTable answers an absent
    table or schema with HTTP 200, an empty ColumnList and the requested path echoed back."""
    workgroup = _serverless_workgroup(ctx)
    rsd = ctx.client("redshift-data")
    table = ctx.unique_name("sim2real_behav_cat_")

    databases = rsd.list_databases(WorkgroupName=workgroup, Database=_DATABASE)["Databases"]
    assert _DATABASE in databases, (
        f"the namespace's own database must be listed, got {databases!r}"
    )
    schemas = rsd.list_schemas(WorkgroupName=workgroup, Database=_DATABASE)["Schemas"]
    assert "public" in schemas, f"'public' must be listed, got {schemas!r}"

    before = rsd.list_tables(
        WorkgroupName=workgroup, Database=_DATABASE, SchemaPattern="public",
        TablePattern=table,
    )["Tables"]
    assert before == [], (
        f"the table has not been created yet, so ListTables must be empty, got {before!r}"
    )
    absent = rsd.describe_table(
        WorkgroupName=workgroup, Database=_DATABASE, Schema="public", Table=table
    )
    assert absent["ColumnList"] == [], (
        f"DescribeTable on a table that does not exist must answer an EMPTY ColumnList rather than "
        f"an error, got {absent['ColumnList']!r}"
    )
    assert absent["TableName"] == f"{_DATABASE}.public.{table}", (
        f"DescribeTable must echo the requested path even when nothing is there, got "
        f"{absent['TableName']!r}"
    )

    _must_finish(
        rsd, workgroup,
        f"create table {table}(id int, name varchar(32), amt decimal(9,3))",
    )

    listed = rsd.list_tables(
        WorkgroupName=workgroup, Database=_DATABASE, SchemaPattern="public",
        TablePattern=table,
    )["Tables"]
    assert listed == [{"name": table, "schema": "public", "type": "TABLE"}], (
        f"ListTables must now report exactly the created table as a TABLE, got {listed!r}"
    )

    described = rsd.describe_table(
        WorkgroupName=workgroup, Database=_DATABASE, Schema="public", Table=table
    )
    assert described["TableName"] == f"{_DATABASE}.public.{table}", (
        f"unexpected TableName {described['TableName']!r}"
    )
    assert [(c["name"], c["typeName"], c["precision"], c["scale"], c["length"])
            for c in described["ColumnList"]] == [
        ("id", "int4", 10, 0, 10),
        ("name", "varchar", 32, 0, 32),
        ("amt", "numeric", 9, 3, 9),
    ], (
        f"DescribeTable must report each column's type, precision, scale AND a populated length; "
        f"got {described['ColumnList']!r}"
    )

    # The same columns read through the data path carry length 0 — the two surfaces disagree.
    selected = _must_finish(rsd, workgroup, f"select id, name, amt from {table}")
    result_columns = rsd.get_statement_result(Id=selected["Id"])["ColumnMetadata"]
    assert [c["length"] for c in result_columns] == [0, 0, 0], (
        f"GetStatementResult's ColumnMetadata must report length 0 where DescribeTable reports the "
        f"declared width; got {[c['length'] for c in result_columns]!r}"
    )
    assert [c["typeName"] for c in result_columns] == ["int4", "varchar", "numeric"], (
        f"the two surfaces must agree on typeName; got "
        f"{[c['typeName'] for c in result_columns]!r}"
    )

    wrong_schema = rsd.describe_table(
        WorkgroupName=workgroup, Database=_DATABASE, Schema="sim2real_no_such_schema",
        Table=table,
    )
    assert wrong_schema["ColumnList"] == [], (
        f"a schema that does not exist must answer an EMPTY ColumnList rather than an error, got "
        f"{wrong_schema['ColumnList']!r}"
    )
    assert wrong_schema["TableName"] == f"{_DATABASE}.sim2real_no_such_schema.{table}", (
        f"DescribeTable must echo the nonexistent schema back in TableName, got "
        f"{wrong_schema['TableName']!r}"
    )

    no_schema = rsd.describe_table(
        WorkgroupName=workgroup, Database=_DATABASE, Table=table
    )
    assert no_schema["TableName"] == f"{_DATABASE}..{table}", (
        f"omitting Schema must produce a DOUBLE-DOT TableName, got {no_schema['TableName']!r}"
    )
    assert [c["name"] for c in no_schema["ColumnList"]] == ["id", "name", "amt"], (
        f"omitting Schema must still resolve the columns, got {no_schema['ColumnList']!r}"
    )

    _must_finish(rsd, workgroup, f"drop table {table}")

    after = rsd.list_tables(
        WorkgroupName=workgroup, Database=_DATABASE, SchemaPattern="public",
        TablePattern=table,
    )["Tables"]
    assert after == [], f"ListTables must be empty after the DROP, got {after!r}"
    dropped = rsd.describe_table(
        WorkgroupName=workgroup, Database=_DATABASE, Schema="public", Table=table
    )
    assert dropped["ColumnList"] == [], (
        f"DescribeTable after the DROP must answer an EMPTY ColumnList rather than a not-found "
        f"error, got {dropped['ColumnList']!r}"
    )
    assert dropped["TableName"] == f"{_DATABASE}.public.{table}", (
        f"and it must still echo the path of the table that is gone, got {dropped['TableName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
