"""json-and-csv-result-readers-are-mutually-exclusive."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "json-and-csv-result-readers-are-mutually-exclusive"
GROUP = 'result-format'
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


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetStatementResult and GetStatementResultV2 refuse each other's ResultFormat with a 400
    ValidationException, so the submit's ResultFormat decides the reader; the JSON and CSV renderings
    of the same DECIMAL, double, boolean and NULL values differ as asserted."""
    workgroup = _serverless_workgroup(ctx)
    rsd = ctx.client("redshift-data")
    table = ctx.unique_name("sim2real_behav_fmt_")

    _must_finish(
        rsd, workgroup,
        f"create table {table}(i int, amt decimal(9,3), dbl double precision, "
        f"flag boolean, note varchar(16))",
    )
    _must_finish(
        rsd, workgroup,
        f"insert into {table} values (1, 1.500, 2.5, true, null)",
    )
    select = f"select i, amt, dbl, flag, note from {table} order by i"

    json_stmt = _must_finish(rsd, workgroup, select)
    assert json_stmt["ResultFormat"] == "json", (
        f"a statement submitted with no ResultFormat must report 'json', got "
        f"{json_stmt.get('ResultFormat')!r}"
    )
    assert json_stmt["HasResultSet"] is True, (
        f"the select must report a result set, got {json_stmt.get('HasResultSet')!r}"
    )
    assert json_stmt["ResultRows"] == 1, (
        f"the select must report 1 row, got {json_stmt.get('ResultRows')!r}"
    )

    json_result = rsd.get_statement_result(Id=json_stmt["Id"])
    assert json_result["TotalNumRows"] == 1, (
        f"TotalNumRows must be 1, got {json_result.get('TotalNumRows')!r}"
    )
    assert json_result["Records"] == [[
        {"longValue": 1},
        {"stringValue": "1.500"},
        {"doubleValue": 2.5},
        {"booleanValue": True},
        {"isNull": True},
    ]], (
        f"the json Field discriminators are wrong — a DECIMAL must be a stringValue carrying its "
        f"trailing zeros while a double precision must be a doubleValue; got "
        f"{json_result['Records']!r}"
    )
    assert [c["typeName"] for c in json_result["ColumnMetadata"]] == [
        "int4", "numeric", "float8", "bool", "varchar"
    ], f"unexpected ColumnMetadata typeNames {[c['typeName'] for c in json_result['ColumnMetadata']]!r}"

    v2_on_json = _rejection(lambda: rsd.get_statement_result_v2(Id=json_stmt["Id"]))
    assert v2_on_json[0] == "ValidationException", (
        f"GetStatementResultV2 on a json statement must be rejected ValidationException, got "
        f"{v2_on_json[0]!r}"
    )
    assert v2_on_json[1] == 400, f"expected HTTP 400, got {v2_on_json[1]!r}"
    assert v2_on_json[2] == (
        "GetStatementResultV2 can only return results that are in CSV format. Try using "
        "GetStatementResult instead for JSON format"
    ), f"unexpected v2-on-json message {v2_on_json[2]!r}"

    csv_stmt = _must_finish(rsd, workgroup, select, ResultFormat="CSV")
    assert csv_stmt["ResultFormat"] == "csv", (
        f"a ResultFormat='CSV' statement must report 'csv', got {csv_stmt.get('ResultFormat')!r}"
    )

    v1_on_csv = _rejection(lambda: rsd.get_statement_result(Id=csv_stmt["Id"]))
    assert v1_on_csv[0] == "ValidationException", (
        f"GetStatementResult on a csv statement must be rejected ValidationException, got "
        f"{v1_on_csv[0]!r}"
    )
    assert v1_on_csv[1] == 400, f"expected HTTP 400, got {v1_on_csv[1]!r}"
    assert v1_on_csv[2] == (
        "GetStatementResult can only return results that are in JSON format. Try using "
        "GetStatementResultV2 for other result formats"
    ), f"unexpected v1-on-csv message {v1_on_csv[2]!r}"

    csv_result = rsd.get_statement_result_v2(Id=csv_stmt["Id"])
    assert csv_result["ResultFormat"] == "csv", (
        f"GetStatementResultV2 must echo ResultFormat 'csv', got {csv_result.get('ResultFormat')!r}"
    )
    assert csv_result["TotalNumRows"] == 1, (
        f"TotalNumRows must be 1, got {csv_result.get('TotalNumRows')!r}"
    )
    assert csv_result["Records"] == [{"CSVRecords": "i,amt,dbl,flag,note\r\n1,1.500,2.5,true,\r\n"}], (
        f"the csv rendering must be ONE CSVRecords blob carrying a header row, CRLF terminators, "
        f"'true' spelled out for the boolean and an EMPTY field for the NULL; got {csv_result['Records']!r}"
    )
    assert [c["typeName"] for c in csv_result["ColumnMetadata"]] == [
        "int4", "numeric", "float8", "bool", "varchar"
    ], "both readers must report identical ColumnMetadata typeNames"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
