"""jdbc-database-metadata-maps-external-table-to-table-and-view-to-view."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path

from behavioral_harness import tags

CHECK = "jdbc-database-metadata-maps-external-table-to-table-and-view-to-view"
GROUP = "metadata"
SERVICES = ["athena"]

# The driver docs state that getTables reports Athena external tables as `TABLE` and views as
# `VIEW`, and that filters must use those JDBC names, not EXTERNAL_TABLE or VIRTUAL_VIEW.
# Passing the Athena names makes the driver raise IllegalArgumentException.

# The uber jar bundles the streaming client that speaks the port-444 streaming service.
_JDBC_VERSION = "3.8.1"
_JDBC_JAR_URL = (
    "https://downloads.athena.us-east-1.amazonaws.com/drivers/JDBC/3.8.1/"
    "athena-jdbc-3.8.1-with-dependencies.jar"
)
_JAR_NAME = "athena-jdbc-3.8.1-with-dependencies.jar"
_DRIVER_CLASS_ENTRY = "com/amazon/athena/jdbc/AthenaDriver.class"
# A JDK (not a JRE) because the probe is compiled in-container; the driver needs Java 8+.
_JDK_IMAGE = "public.ecr.aws/amazoncorretto/amazoncorretto:21"
# Marks the probe's one JSON line among SLF4J/driver output.
_SENTINEL = "__SIM2REAL_JSON__"

_JAVA_TIMEOUT_S = 600.0
_JAR_PATH = Path.home() / ".cache" / "sim2real" / _JAR_NAME


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object, then the bucket: Athena writes result and metadata objects into the
    output location, so DeleteBucket alone would fail."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={
            "TagSet": [
                {"Key": "sim2real", "Value": CHECK[:250]},
                {"Key": "sim2real:managed", "Value": "true"},
            ]
        },
    )
    return bucket


def _output_location(ctx):
    return f"s3://{_make_bucket(ctx, 'sim2real-behav-athena-results-')}/results/"


def _start_query(athena, out, query_string, workgroup=None, database=None, **extra):
    kwargs = {"QueryString": query_string, "ResultConfiguration": {"OutputLocation": out}}
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    kwargs.update(extra)
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


def _wait_terminal(athena, qid, timeout_s=300.0, interval_s=2.0):
    """Poll GetQueryExecution to a terminal state; 300s because a query over an external table
    also pays Glue metadata resolution, split planning and S3 listing."""
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})"
    )


def _run_sql(athena, out, sql, database=None, workgroup=None, **extra):
    """Run a statement to SUCCEEDED or raise, naming the engine's own reason."""
    qid = _start_query(athena, out, sql, database=database, workgroup=workgroup, **extra)
    state = _wait_terminal(athena, qid)
    if state != "SUCCEEDED":
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        raise AssertionError(
            f"statement reached {state}, expected SUCCEEDED: {sql[:200]!r} -- "
            f"{status.get('StateChangeReason')}"
        )
    return qid


def _dml_name(database, table):
    """Double-quoted name for a DML statement: Athena parses DDL with Hive (backticks) but DML
    with Trino (double quotes), and rejects a backtick in DML."""
    return f'"{database}"."{table}"'


def _api_data_rows(athena, qid):
    """Every GetQueryResults data row for *qid*, header dropped; a NULL Datum has no
    `VarCharValue` key, so it maps to None while an empty string maps to ""."""
    rows = []
    token = None
    while True:
        kwargs = {"QueryExecutionId": qid, "MaxResults": 1000}
        if token:
            kwargs["NextToken"] = token
        page = athena.get_query_results(**kwargs)
        rows.extend(
            [d.get("VarCharValue") for d in r["Data"]] for r in page["ResultSet"]["Rows"]
        )
        token = page.get("NextToken")
        if not token:
            break
    # Row 0 of page 1 of a SELECT repeats the column labels.
    return rows[1:]


def _require_jdbc_prerequisites():
    """Raise RequiredToolMissing when the driver jar or the JDK image is absent; the jar is
    checked structurally because AWS publishes no checksum for it."""
    from fidelity_tests_runner import RequiredToolMissing

    missing = []
    jar = f"Athena JDBC {_JDBC_VERSION} uber jar at {_JAR_PATH} (pre-seed it from {_JDBC_JAR_URL})"
    if not _JAR_PATH.is_file():
        missing.append(jar)
    elif _JAR_PATH.stat().st_size <= 20_000_000 or not zipfile.is_zipfile(_JAR_PATH):
        missing.append(f"{jar}: the file there is not the >20 MB uber jar")
    else:
        with zipfile.ZipFile(_JAR_PATH) as zf:
            if _DRIVER_CLASS_ENTRY not in set(zf.namelist()):
                missing.append(f"{jar}: the file there has no {_DRIVER_CLASS_ENTRY}")
    seeded = subprocess.run(
        ["docker", "image", "inspect", _JDK_IMAGE],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if seeded.returncode != 0:
        missing.append(f"docker image {_JDK_IMAGE} (pre-seed it on the runner)")
    if missing:
        raise RequiredToolMissing(missing)


def _jar_path():
    """The pinned driver jar, checked by ``_require_jdbc_prerequisites``."""
    return _JAR_PATH


def _jdbc_workspace(ctx):
    """A private (0700) temp dir holding the driver jar, the credential env-file and the Java
    probe; removed at teardown because it holds session credentials."""
    ws = Path(tempfile.mkdtemp(prefix="sim2real-athena-jdbc-"))
    ws.chmod(0o700)
    ctx.on_cleanup(lambda: shutil.rmtree(ws, ignore_errors=True))
    shutil.copy2(_jar_path(), ws / _JAR_NAME)
    env = ctx.subprocess_env()
    lines = [
        f"{k}={env[k]}"
        for k in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_REGION",
            "AWS_DEFAULT_REGION",
            "AWS_ENDPOINT_URL",
        )
        if env.get(k)
    ]
    assert lines, (
        "ctx.subprocess_env() carried no AWS_* variables, so the container would sign with no "
        "identity at all; the JDBC driver's DefaultChain has nothing else to read in a container"
    )
    env_file = ws / "aws.env"
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    env_file.chmod(0o600)
    return ws


def _driver_properties(ctx, out, database=None, extra=None):
    """The JDBC 3.x connection properties for this target; endpoints follow ctx.subprocess_env()."""
    # The driver spells the workgroup property `WorkGroup`; unknown properties are silently ignored.
    props = {
        "Region": ctx.region,
        "OutputLocation": out,
        "Catalog": "AwsDataCatalog",
        "CredentialsProvider": "DefaultChain",
    }
    if database:
        props["Database"] = database
    # The driver's SDK reads Athena's and S3's endpoint from the environment it is given; its
    # streaming client takes none, so it gets the Athena host on port 444, resolved by ctx.
    props["AthenaStreamingEndpoint"] = ctx.service_url(
        f"https://athena.{ctx.region}.amazonaws.com:444")
    props.update(extra or {})
    for key, value in props.items():
        assert "\\" not in value and "\n" not in value, (
            f"driver property {key}={value!r} would be mangled by java.util.Properties escaping; "
            f"no value this check builds may contain a backslash or a newline"
        )
    return props


def _run_java(ctx, ws, cls, source, args=(), *, props=None, sql=None, timeout_s=_JAVA_TIMEOUT_S):
    """Compile and run a one-class JDBC probe in a pinned JDK container; return its JSON line.
    SQL goes through a file so no shell or Java quoting can alter it."""
    (ws / f"{cls}.java").write_text(source, encoding="utf-8")
    if props is not None:
        (ws / "probe.properties").write_text(
            "".join(f"{k}={v}\n" for k, v in props.items()), encoding="utf-8"
        )
    if sql is not None:
        (ws / "probe.sql").write_text(sql, encoding="utf-8")
    for a in args:
        assert "'" not in str(a), (
            f"probe argument {a!r} contains a single quote, which would break the container's "
            f"shell quoting; every argument this check passes is a number or a generated identifier"
        )
    quoted = " ".join(f"'{a}'" for a in args)
    cmd = [
        "docker",
        "run",
        "--rm",
        "--pull",
        "never",
        "--network",
        "host",
        "--env-file",
        str(ws / "aws.env"),
        "-v",
        f"{ws}:/w",
        "-w",
        "/w",
        _JDK_IMAGE,
        "sh",
        "-c",
        f"javac -cp /w/{_JAR_NAME} {cls}.java && java -cp /w/{_JAR_NAME}:/w {cls} {quoted}",
    ]
    # side-channel: --network host lets the JDBC driver reach the check's endpoint (a runner loopback
    # address on an emulator target); the JDK image is a runner prerequisite run with --pull never,
    # so nothing is pulled, and _require_jdbc_prerequisites reports its absence as tool_missing.
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith(_SENTINEL)]
    assert len(lines) == 1, (
        f"the JDBC probe must print exactly one {_SENTINEL} line; got {len(lines)} "
        f"(rc={proc.returncode}) stderr_tail={proc.stderr[-400:]!r} "
        f"stdout_tail={proc.stdout[-200:]!r}"
    )
    return json.loads(lines[0][len(_SENTINEL) :])


def _external_table(ctx, athena, out, rows_csv, columns):
    """One CSV object in S3 registered as a typed EXTERNAL TABLE; returns (database, table,
    data_bucket, data_bytes). Cleanup is LIFO, so the results bucket outlives DROP DATABASE."""
    s3 = ctx.client("s3")
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")
    body = rows_csv.encode()
    s3.put_object(Bucket=data_bucket, Key="data/rows.csv", Body=body)

    database = ctx.unique_name("sim2real_behav_db_").replace("-", "_")
    table = ctx.unique_name("sim2real_behav_tbl_").replace("-", "_")
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena,
        out,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` ({columns}) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/data/'",
    )
    return database, table, data_bucket, len(body)


_CSV_ROWS = "1,alpha\n2,bravo\n3,charlie\n"
_COLUMNS = "`id` int, `name` string"

# The Athena API's own names for the two objects, which the driver must translate.
_ATHENA_TABLE_TYPE = "EXTERNAL_TABLE"
_ATHENA_VIEW_TYPE = "VIRTUAL_VIEW"
_JDBC_TABLE_TYPE = "TABLE"
_JDBC_VIEW_TYPE = "VIEW"

_META_JAVA = r"""
import java.io.FileReader;
import java.io.Reader;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Properties;

public class Meta {

    static String esc(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') {
                b.append('\\').append(c);
            } else if (c == '\n') {
                b.append("\\n");
            } else if (c == '\r') {
                b.append("\\r");
            } else if (c == '\t') {
                b.append("\\t");
            } else if (c < 0x20) {
                b.append(String.format("\\u%04x", (int) c));
            } else {
                b.append(c);
            }
        }
        return b.append('"').toString();
    }

    /* One getTables() call rendered as a JSON array of the four JDBC-standard columns. */
    static String tables(DatabaseMetaData md, String cat, String schema, String pattern,
                         String[] types) throws Exception {
        StringBuilder b = new StringBuilder("[");
        try (ResultSet rs = md.getTables(cat, schema, pattern, types)) {
            int n = 0;
            while (rs.next()) {
                if (n > 0) {
                    b.append(',');
                }
                b.append("{\"cat\":").append(esc(rs.getString("TABLE_CAT")))
                    .append(",\"schem\":").append(esc(rs.getString("TABLE_SCHEM")))
                    .append(",\"name\":").append(esc(rs.getString("TABLE_NAME")))
                    .append(",\"type\":").append(esc(rs.getString("TABLE_TYPE")))
                    .append('}');
                n++;
            }
        }
        return b.append(']').toString();
    }

    public static void main(String[] argv) {
        String json;
        try {
            json = probe(argv);
        } catch (Throwable t) {
            json = "{\"ok\":false,\"errorClass\":" + esc(t.getClass().getName())
                + ",\"message\":" + esc(t.getMessage()) + "}";
        }
        System.out.println("__SIM2REAL_JSON__" + json);
        System.out.flush();
    }

    static String probe(String[] argv) throws Exception {
        String catalog = argv[0];
        String schema = argv[1];
        String pattern = argv[2];
        Properties p = new Properties();
        try (Reader r = new FileReader("/w/probe.properties")) {
            p.load(r);
        }
        java.sql.Driver drv = new com.amazon.athena.jdbc.AthenaDriver();
        try (Connection c = drv.connect("jdbc:athena://", p)) {
            DatabaseMetaData md = c.getMetaData();
            StringBuilder b = new StringBuilder("{\"ok\":true");
            b.append(",\"all\":").append(tables(md, catalog, schema, pattern, null));
            b.append(",\"tableFilter\":")
                .append(tables(md, catalog, schema, pattern, new String[] {"TABLE"}));
            b.append(",\"viewFilter\":")
                .append(tables(md, catalog, schema, pattern, new String[] {"VIEW"}));
            /* The Athena vocabulary the docs tell you NOT to pass. Reported, never swallowed:
               whichever way it goes, the python side asserts on it. The tables() call is
               evaluated into a local BEFORE anything is appended to `b`: appending the
               "athenaNameFilter" key first and letting tables() throw as an argument to the
               next append leaves a dangling, valueless key in `b` that the catch block's own
               "athenaNameFilter" key then duplicates, producing invalid JSON. Measured against
               real AWS 2026-09-17: the driver raises here, so this is not a hypothetical. */
            try {
                String athenaNameFilter = tables(md, catalog, schema, pattern,
                    new String[] {"EXTERNAL_TABLE", "VIRTUAL_VIEW"});
                b.append(",\"athenaNameFilter\":").append(athenaNameFilter);
                b.append(",\"athenaNameFilterError\":null");
            } catch (Throwable t) {
                b.append(",\"athenaNameFilter\":null,\"athenaNameFilterError\":")
                    .append(esc(t.getClass().getName() + ": " + t.getMessage()));
            }
            b.append(",\"tableTypes\":[");
            try (ResultSet rs = md.getTableTypes()) {
                int n = 0;
                while (rs.next()) {
                    if (n > 0) {
                        b.append(',');
                    }
                    b.append(esc(rs.getString("TABLE_TYPE")));
                    n++;
                }
            }
            b.append("]}");
            return b.toString();
        }
    }
}
"""


@tags("axis:happy-path", "cap:c3", "concern:representation", "dp:native", "plane:data")
def run(ctx) -> None:
    """`DatabaseMetaData.getTables` reports an Athena EXTERNAL_TABLE as JDBC `TABLE` and a
    VIRTUAL_VIEW as JDBC `VIEW`, and the Athena spellings do not work as type filters.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/jdbc-v3-driver.html
    """
    from fidelity_tests_runner import require_tools

    require_tools("docker")
    _require_jdbc_prerequisites()

    athena = ctx.client("athena")
    out = _output_location(ctx)
    database, table, _, _ = _external_table(ctx, athena, out, _CSV_ROWS, _COLUMNS)

    # CREATE VIEW is Trino DML, so it needs double-quoted identifiers.
    view = ctx.unique_name("sim2real_behav_vw_").replace("-", "_")
    _run_sql(
        athena,
        out,
        f"CREATE VIEW {_dml_name(database, view)} AS "
        f"SELECT id, name FROM {_dml_name(database, table)}",
        database=database,
    )
    # DROP DATABASE CASCADE removes the view too; this makes a failed view drop visible.
    ctx.on_cleanup(
        lambda: _run_sql(athena, out, f"DROP VIEW IF EXISTS {_dml_name(database, view)}")
    )

    table_meta = athena.get_table_metadata(
        CatalogName="AwsDataCatalog", DatabaseName=database, TableName=table
    )["TableMetadata"]
    view_meta = athena.get_table_metadata(
        CatalogName="AwsDataCatalog", DatabaseName=database, TableName=view
    )["TableMetadata"]
    assert table_meta["TableType"] == _ATHENA_TABLE_TYPE, (
        f"the Athena API must still call the table {_ATHENA_TABLE_TYPE} — that is the whole point "
        f"of the translation; GetTableMetadata said {table_meta.get('TableType')!r}"
    )
    assert view_meta["TableType"] == _ATHENA_VIEW_TYPE, (
        f"the Athena API must still call the view {_ATHENA_VIEW_TYPE}; GetTableMetadata said "
        f"{view_meta.get('TableType')!r}"
    )

    ws = _jdbc_workspace(ctx)
    payload = _run_java(
        ctx,
        ws,
        "Meta",
        _META_JAVA,
        args=("AwsDataCatalog", database, "sim2real%"),
        props=_driver_properties(ctx, out, database=database),
    )
    assert payload.get("ok") is True, (
        f"DatabaseMetaData.getTables must succeed; the driver reported {str(payload)[:300]}"
    )

    by_name = {row["name"]: row for row in payload["all"]}
    assert set(by_name) == {table, view}, (
        f"getTables must list exactly the table and the view this check created in database "
        f"{database}; it listed {sorted(by_name)}"
    )
    assert by_name[table]["type"] == _JDBC_TABLE_TYPE, (
        f"an Athena {_ATHENA_TABLE_TYPE} must be reported to JDBC as {_JDBC_TABLE_TYPE!r} "
        f"(jdbc-v3-driver.html); getTables said {by_name[table]['type']!r}"
    )
    assert by_name[view]["type"] == _JDBC_VIEW_TYPE, (
        f"an Athena {_ATHENA_VIEW_TYPE} must be reported to JDBC as {_JDBC_VIEW_TYPE!r} "
        f"(jdbc-v3-driver.html); getTables said {by_name[view]['type']!r}"
    )
    for name, row in by_name.items():
        assert (row["cat"], row["schem"]) == ("AwsDataCatalog", database), (
            f"{name}: the Athena catalog must map to TABLE_CAT and the Athena database to "
            f"TABLE_SCHEM; got cat={row['cat']!r} schem={row['schem']!r}"
        )

    assert [r["name"] for r in payload["tableFilter"]] == [table], (
        f"types={{'{_JDBC_TABLE_TYPE}'}} must select the external table and nothing else; got "
        f"{[(r['name'], r['type']) for r in payload['tableFilter']]}"
    )
    assert [r["name"] for r in payload["viewFilter"]] == [view], (
        f"types={{'{_JDBC_VIEW_TYPE}'}} must select the view and nothing else; got "
        f"{[(r['name'], r['type']) for r in payload['viewFilter']]}"
    )

    # The driver raises IllegalArgumentException for an Athena type name rather than matching nothing.
    athena_filter = payload["athenaNameFilter"]
    athena_filter_error = payload["athenaNameFilterError"]
    assert athena_filter is None and athena_filter_error, (
        f"the docs say not to pass Athena table-type names to getTables, and the driver must RAISE "
        f"rather than silently match nothing when types={{'{_ATHENA_TABLE_TYPE}',"
        f"'{_ATHENA_VIEW_TYPE}'}}; got athenaNameFilter={athena_filter!r} "
        f"error={athena_filter_error!r}"
    )
    assert "IllegalArgumentException" in athena_filter_error and _ATHENA_TABLE_TYPE in athena_filter_error, (
        f"the driver must reject an Athena table-type name filter with an "
        f"IllegalArgumentException naming the offending type {_ATHENA_TABLE_TYPE!r}; got "
        f"{athena_filter_error!r}"
    )

    # getTableTypes feeds a schema browser's filter list, so it must use JDBC names too.
    types = payload["tableTypes"]
    assert _JDBC_TABLE_TYPE in types and _JDBC_VIEW_TYPE in types, (
        f"getTableTypes must advertise the JDBC names {_JDBC_TABLE_TYPE!r} and "
        f"{_JDBC_VIEW_TYPE!r}; it advertised {types}"
    )
    assert _ATHENA_TABLE_TYPE not in types and _ATHENA_VIEW_TYPE not in types, (
        f"getTableTypes must NOT advertise Athena's own names; it advertised {types}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
