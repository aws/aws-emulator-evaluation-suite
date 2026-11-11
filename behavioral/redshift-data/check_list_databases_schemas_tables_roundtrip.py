"""list-databases-schemas-tables-roundtrip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "list-databases-schemas-tables-roundtrip"
GROUP = "data-plane"
SERVICES = ["redshift-data"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Schemas, tables and columns created via SQL are discoverable through ListDatabases, ListSchemas,
    ListTables and DescribeTable, and SchemaPattern/TablePattern actually narrow the results.
    """
    _require_live_backend(ctx)
    wg = _provision_workgroup(ctx)
    rd = ctx.client("redshift-data")
    schema_a = ctx.unique_name("sim2real_schema_a_").replace("-", "_")
    schema_b = ctx.unique_name("sim2real_schema_b_").replace("-", "_")

    for schema in (schema_a, schema_b):
        _, final = _execute_and_wait(rd, wg, f"CREATE SCHEMA {schema}")
        assert final["Status"] == "FINISHED", final.get("Error")

    _, final = _execute_and_wait(rd, wg, f"CREATE TABLE {schema_a}.tbl1 (id INT, name VARCHAR(20))")
    assert final["Status"] == "FINISHED", final.get("Error")
    _, final = _execute_and_wait(rd, wg, f"CREATE TABLE {schema_b}.tbl2 (id INT)")
    assert final["Status"] == "FINISHED", final.get("Error")

    dbs = rd.list_databases(WorkgroupName=wg["workgroup"], Database=wg["database"])["Databases"]
    assert wg["database"] in dbs, dbs

    schemas = rd.list_schemas(
        WorkgroupName=wg["workgroup"], Database=wg["database"], SchemaPattern=schema_a
    )["Schemas"]
    assert schema_a in schemas, schemas
    assert schema_b not in schemas, schemas

    tables = rd.list_tables(
        WorkgroupName=wg["workgroup"],
        Database=wg["database"],
        SchemaPattern=schema_a,
        TablePattern="tbl1",
    )["Tables"]
    table_names = [(t["schema"], t["name"]) for t in tables]
    assert (schema_a, "tbl1") in table_names, table_names
    assert (schema_b, "tbl2") not in table_names, table_names

    described = rd.describe_table(
        WorkgroupName=wg["workgroup"], Database=wg["database"], Schema=schema_a, Table="tbl1"
    )
    expected_table_name = f"{wg['database']}.{schema_a}.tbl1"
    assert described["TableName"] == expected_table_name, (
        f"expected TableName {expected_table_name!r}, got {described['TableName']!r}"
    )
    col_names = {c["name"] for c in described["ColumnList"]}
    assert col_names == {"id", "name"}, col_names


def _require_live_backend(ctx) -> None:
    # redshift-data's data plane IS the AWS API (ExecuteStatement/DescribeStatement/...) — this
    # is not a native-protocol side-channel, so there is nothing to require here. The workgroup
    # is always provisioned for real; the harness's heavy-service timeout/concurrency budget
    # covers Redshift Serverless's multi-minute workgroup provisioning.
    return


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
        status = rss.get_namespace(namespaceName=ns).get("namespace", {}).get("status")
        return status in (None, "AVAILABLE")
    except Exception:
        return False


def _workgroup_status(rss, wg):
    try:
        return rss.get_workgroup(workgroupName=wg)["workgroup"]["status"]
    except Exception:
        return None


def _provision_workgroup(ctx) -> dict:
    rss = ctx.client("redshift-serverless")
    ns = ctx.unique_name("sim2real-rsns-")
    wg = ctx.unique_name("sim2real-rswg-")

    rss.create_namespace(
        namespaceName=ns, dbName="dev", tags=[{"key": "sim2real-behavioral", "value": "true"}]
    )

    def _cleanup_ns():
        try:
            rss.delete_namespace(namespaceName=ns)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_ns)
    _poll_until(lambda: _namespace_ready(rss, ns), lambda ok: ok, timeout_s=180, interval_s=5)

    rss.create_workgroup(
        workgroupName=wg, namespaceName=ns, tags=[{"key": "sim2real-behavioral", "value": "true"}], subnetIds=ctx.network().subnet_ids
    )

    def _cleanup_wg():
        try:
            rss.delete_workgroup(workgroupName=wg)
            _poll_until(lambda: _workgroup_status(rss, wg), lambda s: s is None, timeout_s=300, interval_s=10)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

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
