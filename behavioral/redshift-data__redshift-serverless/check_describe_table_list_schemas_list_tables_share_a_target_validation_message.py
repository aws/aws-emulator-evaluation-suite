"""describe-table-list-schemas-list-tables-share-a-target-validation-message."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "describe-table-list-schemas-list-tables-share-a-target-validation-message"
GROUP = "overly-permissive"
SERVICES = ["redshift-data", "redshift-serverless"]

_TARGET_MESSAGE = "There should be only one of the following: ClusterIdentifier, WorkgroupName"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeTable, ListSchemas and ListTables each reject a missing or doubled target with
    the same ValidationException message naming only ClusterIdentifier and WorkgroupName, and
    a single valid target still reads the table this check created."""
    wg = _provision_workgroup(ctx)
    rd = ctx.client("redshift-data")
    table = ctx.unique_name("sim2real_target_").replace("-", "_")

    _, create_final = _execute_and_wait(rd, wg, f"CREATE TABLE {table} (id int)")
    assert create_final["Status"] == "FINISHED", (
        f"expected CREATE TABLE to succeed on the real engine, got {create_final['Status']!r} "
        f"(error={create_final.get('Error')!r})"
    )

    for op, kwargs in (
        (rd.describe_table, dict(Database=wg["database"], Table=table)),
        (rd.list_schemas, dict(Database=wg["database"])),
        (rd.list_tables, dict(Database=wg["database"], TablePattern=table)),
    ):
        # negative 1: no ClusterIdentifier, no WorkgroupName
        code, msg = _client_error(lambda op=op, kwargs=kwargs: op(**kwargs))
        assert code == "ValidationException", f"{op.__name__}: expected ValidationException, got {code}"
        assert msg == _TARGET_MESSAGE, f"{op.__name__}: {msg!r}"

        # negative 2: both ClusterIdentifier and WorkgroupName
        code, msg = _client_error(
            lambda op=op, kwargs=kwargs: op(ClusterIdentifier="sim2real-bogus-cluster", WorkgroupName=wg["workgroup"], **kwargs)
        )
        assert code == "ValidationException", f"{op.__name__}: expected ValidationException, got {code}"
        assert msg == _TARGET_MESSAGE, f"{op.__name__}: {msg!r}"

    # positive control: a single valid target reads the table this check created
    described = rd.describe_table(Database=wg["database"], Table=table, WorkgroupName=wg["workgroup"])
    column_names = {c["name"] for c in described["ColumnList"]}
    assert column_names == {"id"}, f"expected DescribeTable to show column 'id', got {sorted(column_names)}"

    tables = rd.list_tables(Database=wg["database"], TablePattern=table, WorkgroupName=wg["workgroup"])["Tables"]
    table_names = {t["name"] for t in tables}
    assert table_names == {table}, f"expected ListTables to show only {table!r}, got {sorted(table_names)}"


# ===== self-contained helpers =====


def _client_error(fn):
    """Call fn() and return its error as (code, message). An unexpected SUCCESS raises, because
    a target accepting a call AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _namespace_ready(rss, ns) -> bool:
    try:
        status = rss.get_namespace(namespaceName=ns)["namespace"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise
    return status == "AVAILABLE"


def _workgroup_status(rss, wg):
    """The workgroup's status, or None once it no longer exists; any other error raises."""
    try:
        return rss.get_workgroup(workgroupName=wg)["workgroup"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _provision_workgroup(ctx) -> dict:
    rss = ctx.client("redshift-serverless")
    ns = ctx.unique_name("sim2real-rsns-")
    wg = ctx.unique_name("sim2real-rswg-")

    rss.create_namespace(
        namespaceName=ns, dbName="dev", tags=[{"key": "sim2real", "value": CHECK}]
    )

    def _cleanup_ns():
        deadline = time.monotonic() + 45
        while True:
            try:
                rss.delete_namespace(namespaceName=ns)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                transient = code == "ConflictException" and exc.response["Error"].get("Message") == (
                    "There is an operation running on the namespace. Try deleting the namespace again later."
                )
                if transient and time.monotonic() < deadline:
                    time.sleep(5)
                    continue
                raise

    ctx.on_cleanup(_cleanup_ns)
    _poll_until(lambda: _namespace_ready(rss, ns), lambda ok: ok, timeout_s=180, interval_s=5)

    rss.create_workgroup(
        workgroupName=wg, namespaceName=ns, tags=[{"key": "sim2real", "value": CHECK}]
    )

    def _cleanup_wg():
        try:
            rss.delete_workgroup(workgroupName=wg)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        _poll_until(lambda: _workgroup_status(rss, wg), lambda s: s is None, timeout_s=300, interval_s=10)

    ctx.on_cleanup(_cleanup_wg)
    _poll_until(
        lambda: _workgroup_status(rss, wg), lambda s: s == "AVAILABLE", timeout_s=900, interval_s=15
    )
    return {"workgroup": wg, "namespace": ns, "database": "dev"}


def _execute_and_wait(rd, wg, sql, timeout_s=90, **kwargs):
    resp = rd.execute_statement(WorkgroupName=wg["workgroup"], Database=wg["database"], Sql=sql, **kwargs)
    sid = resp["Id"]
    final = _poll_until(
        lambda: rd.describe_statement(Id=sid),
        lambda d: d["Status"] in ("FINISHED", "FAILED", "ABORTED"),
        timeout_s=timeout_s,
        interval_s=1.5,
    )
    return sid, final


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
