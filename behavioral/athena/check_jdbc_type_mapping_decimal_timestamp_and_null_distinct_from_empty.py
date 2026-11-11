"""jdbc-type-mapping-decimal-timestamp-and-null-distinct-from-empty."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path

from behavioral_harness import tags

CHECK = "jdbc-type-mapping-decimal-timestamp-and-null-distinct-from-empty"
GROUP = "representation"
SERVICES = ["athena"]


#: Pinned Athena JDBC 3.x uber jar (https://docs.aws.amazon.com/athena/latest/ug/jdbc-v3-driver.html);
#: it bundles AthenaStreamingJavaClient, which speaks the port-444 streaming service.
_JDBC_VERSION = "3.8.1"
_JDBC_JAR_URL = (
    "https://downloads.athena.us-east-1.amazonaws.com/drivers/JDBC/3.8.1/"
    "athena-jdbc-3.8.1-with-dependencies.jar"
)
_JAR_NAME = "athena-jdbc-3.8.1-with-dependencies.jar"
#: `com.amazon.athena.jdbc.AthenaDriver` per the "Driver class" section of
#: https://docs.aws.amazon.com/athena/latest/ug/jdbc-v3-driver-getting-started.html.
_DRIVER_CLASS_ENTRY = "com/amazon/athena/jdbc/AthenaDriver.class"
#: A JDK (not a JRE) because the probe is compiled in-container; the JDBC 3.x driver needs Java 8+.
_JDK_IMAGE = "public.ecr.aws/amazoncorretto/amazoncorretto:21"
#: Emitted by the Java probe so the check can find its one JSON line among SLF4J/driver noise.
_SENTINEL = "__SIM2REAL_JSON__"

#: javac + JVM start + one Athena query in the pre-seeded JDK image.
_JAVA_TIMEOUT_S = 600.0
#: Where the host provides the pinned driver jar (~25 MB).
_JAR_PATH = Path.home() / ".cache" / "sim2real" / _JAR_NAME


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object, then the bucket: Athena writes `<qid>.csv`, `<qid>.csv.metadata`
    and `<qid>.txt` into the output location, so DeleteBucket alone would fail.
    """
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
    # registered BEFORE the name is used anywhere else
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
    """Poll GetQueryExecution to a required terminal state with a bounded deadline.

    300s because a query also pays metadata resolution, split planning and a shared query queue.
    """
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
    """Fully-qualified table name for a DML statement, double-quoted for the Trino parser.

    Athena parses DDL with Hive (backticks) but DML with Trino; a backticked SELECT is refused
    synchronously with InvalidRequestException "Queries of this type are not supported".
    """
    return f'"{database}"."{table}"'


def _api_data_rows(athena, qid):
    """Every GetQueryResults data row for *qid* as lists of str-or-None, header dropped, all pages.

    A NULL Datum carries no `VarCharValue` key while '' carries `VarCharValue: ""`, so
    `.get("VarCharValue")` keeps NULL and the empty string apart.
    """
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
    """Fail as ``tool_missing`` when the host lacks the driver jar or the JDK image.

    The jar is verified structurally (over 20 MB, a zip, holding the driver class) because AWS
    publishes no checksum for it; the check never downloads the jar or pulls the image.
    """
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
    """A private 0700 temp dir holding the driver jar, the credential env-file and the Java probe.

    It holds session credentials, so it is removed at teardown.
    """
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
    """The JDBC 3.x connection properties for this target.

    Names are as the driver itself lists them: the workgroup property is `WorkGroup`; the
    documented sample's `Workgroup` is silently ignored and would route queries to `primary`.
    """
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

    The SQL goes through a file rather than argv so no shell or Java quoting can alter it.
    """
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
        # Host networking reaches the target endpoint on :443 and the :444 streaming service alike.
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

#: One JDBC probe: connect, run /w/probe.sql, and print one JSON line describing the
#: ResultSetMetaData and every cell (value, wasNull, runtime class). argv is
#: (fetchSize, queryTimeoutSeconds); 0 means "leave the JDBC default alone".
_PROBE_JAVA = r"""
import java.io.FileReader;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

public class Probe {

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

    /* The documented way to recover the execution id: "you unwrap Statement, PreparedStatement,
       and ResultSet instances to the com.amazon.athena.jdbc.AthenaResultSet interface. The
       interface has one method: #getQueryExecutionId"
       -- jdbc-v3-driver-getting-started.html, "Query ID retrieval".
       A failure is REPORTED, never swallowed: it lands in queryExecutionIdError and the python
       side asserts on it, so the check fails loudly and names the cause. */
    static String qidError = null;

    /* How many rows the cursor had already handed over when an exception hit. It is a FIELD and not
       a local so the error branch can report it: "the driver delivered N rows and then failed" is
       the silent-truncation shape a refusal check has to be able to distinguish from "the driver
       delivered nothing". */
    static int rowsRead = 0;

    static String qid(Object o) {
        if (o == null) {
            return null;
        }
        try {
            com.amazon.athena.jdbc.AthenaResultSet a =
                ((java.sql.Wrapper) o).unwrap(com.amazon.athena.jdbc.AthenaResultSet.class);
            return a.getQueryExecutionId();
        } catch (Throwable t) {
            qidError = o.getClass().getName() + " -> " + t.getClass().getName() + ": "
                + t.getMessage();
            return null;
        }
    }

    public static void main(String[] argv) {
        String json;
        try {
            json = probe(argv);
        } catch (Throwable t) {
            json = "{\"ok\":false,\"harnessError\":"
                + esc(t.getClass().getName() + ": " + t.getMessage()) + "}";
        }
        System.out.println("__SIM2REAL_JSON__" + json);
        System.out.flush();
    }

    static String probe(String[] argv) throws Exception {
        int fetchSize = argv.length > 0 ? Integer.parseInt(argv[0]) : 0;
        int queryTimeout = argv.length > 1 ? Integer.parseInt(argv[1]) : 0;
        Properties p = new Properties();
        try (Reader r = new FileReader("/w/probe.properties")) {
            p.load(r);
        }
        String sql = new String(Files.readAllBytes(Paths.get("/w/probe.sql")), "UTF-8").trim();
        StringBuilder b = new StringBuilder();
        Connection c = null;
        Statement st = null;
        ResultSet rs = null;
        try {
            java.sql.Driver drv = new com.amazon.athena.jdbc.AthenaDriver();
            c = drv.connect("jdbc:athena://", p);
            st = c.createStatement();
            if (fetchSize > 0) {
                st.setFetchSize(fetchSize);
            }
            if (queryTimeout > 0) {
                st.setQueryTimeout(queryTimeout);
            }
            long t0 = System.nanoTime();
            rs = st.executeQuery(sql);
            ResultSetMetaData md = rs.getMetaData();
            int n = md.getColumnCount();
            b.append("{\"ok\":true,\"columns\":[");
            for (int i = 1; i <= n; i++) {
                if (i > 1) {
                    b.append(',');
                }
                b.append("{\"label\":").append(esc(md.getColumnLabel(i)))
                    .append(",\"type\":").append(md.getColumnType(i))
                    .append(",\"typeName\":").append(esc(md.getColumnTypeName(i)))
                    .append(",\"className\":").append(esc(md.getColumnClassName(i)))
                    .append(",\"precision\":").append(md.getPrecision(i))
                    .append(",\"scale\":").append(md.getScale(i))
                    .append(",\"nullable\":").append(md.isNullable(i))
                    .append('}');
            }
            b.append("],\"rows\":[");
            while (rs.next()) {
                if (rowsRead > 0) {
                    b.append(',');
                }
                b.append('[');
                for (int i = 1; i <= n; i++) {
                    if (i > 1) {
                        b.append(',');
                    }
                    String v = rs.getString(i);
                    boolean wasNull = rs.wasNull();
                    Object o = rs.getObject(i);
                    b.append("{\"s\":").append(esc(v))
                        .append(",\"null\":").append(wasNull)
                        .append(",\"cls\":").append(esc(o == null ? null : o.getClass().getName()))
                        .append('}');
                }
                b.append(']');
                rowsRead++;
            }
            b.append("],\"rowCount\":").append(rowsRead);
            b.append(",\"elapsedMillis\":").append((System.nanoTime() - t0) / 1000000L);
            b.append(",\"queryExecutionId\":").append(esc(qid(rs)));
            b.append(",\"queryExecutionIdError\":").append(esc(qidError)).append('}');
        } catch (SQLException e) {
            String fromStatement = qid(st);
            b.setLength(0);
            b.append("{\"ok\":false,\"errorClass\":").append(esc(e.getClass().getName()))
                .append(",\"sqlState\":").append(esc(e.getSQLState()))
                .append(",\"errorCode\":").append(e.getErrorCode())
                .append(",\"message\":").append(esc(e.getMessage()))
                .append(",\"causeChain\":").append(esc(chain(e)))
                .append(",\"rowsBeforeError\":").append(rowsRead)
                .append(",\"queryExecutionId\":").append(esc(fromStatement))
                .append(",\"queryExecutionIdError\":").append(esc(qidError)).append('}');
        } finally {
            close(rs);
            close(st);
            close(c);
        }
        return b.toString();
    }

    static String chain(Throwable t) {
        StringBuilder b = new StringBuilder();
        for (Throwable x = t; x != null && b.length() < 4000; x = x.getCause()) {
            if (b.length() > 0) {
                b.append(" | ");
            }
            b.append(x.getClass().getName()).append(": ").append(x.getMessage());
        }
        return b.toString();
    }

    /* Close failures are appended to qidError rather than dropped, so a driver that cannot close
       a handle is still visible in the check's failure text. */
    static void close(AutoCloseable x) {
        if (x == null) {
            return;
        }
        try {
            x.close();
        } catch (Exception e) {
            qidError = (qidError == null ? "" : qidError + " | ") + "close("
                + x.getClass().getName() + "): " + e.getClass().getName();
        }
    }
}
"""


def _jdbc_rows(payload):
    """The probe's rows as lists of str-or-None, so they compare directly with _api_data_rows."""
    return [[None if cell["null"] else cell["s"] for cell in row] for row in payload["rows"]]


#: java.sql.Types constants, spelled out because the container prints numbers.
_TYPES = {
    "INTEGER": 4,
    "BIGINT": -5,
    "DOUBLE": 8,
    "DECIMAL": 3,
    "VARCHAR": 12,
    "BOOLEAN": 16,
    "TIMESTAMP": 93,
    "DATE": 91,
}
#: What a length-less `CAST(NULL AS VARCHAR)` reports. A VARCHAR literal does not: Trino types it
#: as a bounded `varchar(n)` sized to its own character count, so `'plain'` reports precision 5.
_UNBOUNDED_STRING_PRECISION = 2147483647
#: Trino types a VARCHAR literal as `varchar(n)` where n is its own character count — this is what
#: `string_col`'s precision must equal, derived from the literal rather than a guessed number.
_STRING_LITERAL = "plain"
#: 24 integer digits + 9 fractional = 33 significant digits, inside DECIMAL(38,9), so the cast is
#: lossless.
_DECIMAL_LITERAL = "123456789012345678901234.123456789"
_TIMESTAMP_LITERAL = "2026-09-16 04:05:06.789"
#: columnNullableUnknown from java.sql.ResultSetMetaData, reported for every column Athena
#: projects, since ColumnInfo.Nullable is documented as always UNKNOWN.
_NULLABLE_CODE_UNKNOWN = 2


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:native", "plane:data")
def run(ctx) -> None:
    """Over JDBC, DECIMAL keeps its declared precision and scale, TIMESTAMP arrives as a timestamp,
    and NULL is distinguishable from the empty string -- and each agrees with the API rendering.
    """
    from fidelity_tests_runner import require_tools

    require_tools("docker")
    _require_jdbc_prerequisites()

    athena = ctx.client("athena")
    out = _output_location(ctx)

    # Every value is a CAST of a literal declared in the query, so precision, scale and text are
    # exact by construction — no S3 data, no Glue table, nothing inferred from a file.
    sql = (
        f"SELECT CAST('{_DECIMAL_LITERAL}' AS DECIMAL(38,9)) AS dec_col, "
        f"CAST('{_TIMESTAMP_LITERAL}' AS TIMESTAMP) AS ts_col, "
        "CAST(NULL AS VARCHAR) AS null_col, "
        "'' AS empty_col, "
        f"'{_STRING_LITERAL}' AS string_col, "
        "CAST(7 AS INTEGER) AS int_col, "
        "true AS bool_col"
    )

    ws = _jdbc_workspace(ctx)
    payload = _run_java(
        ctx, ws, "Probe", _PROBE_JAVA, args=(0, 0), props=_driver_properties(ctx, out), sql=sql
    )
    assert payload.get("ok") is True, (
        f"the JDBC driver must run the typed SELECT; it reported {str(payload)[:300]}"
    )

    columns = {c["label"]: c for c in payload["columns"]}
    assert list(columns) == [
        "dec_col",
        "ts_col",
        "null_col",
        "empty_col",
        "string_col",
        "int_col",
        "bool_col",
    ], f"ResultSetMetaData must list the projected columns in projection order; got {list(columns)}"

    # --- DECIMAL: the precision and scale the query DECLARED ---------------------------------
    dec = columns["dec_col"]
    assert dec["type"] == _TYPES["DECIMAL"], (
        f"a CAST(... AS DECIMAL(38,9)) column must report java.sql.Types.DECIMAL "
        f"({_TYPES['DECIMAL']}); the driver reported {dec['type']} ({dec['typeName']!r})"
    )
    assert dec["precision"] == 38, (
        f"DECIMAL(38,9) must report getPrecision()==38, got {dec['precision']}"
    )
    assert dec["scale"] == 9, f"DECIMAL(38,9) must report getScale()==9, got {dec['scale']}"

    # --- TIMESTAMP: type code plus the runtime class of the value ----------------------------
    ts = columns["ts_col"]
    assert ts["type"] == _TYPES["TIMESTAMP"], (
        f"a CAST(... AS TIMESTAMP) column must report java.sql.Types.TIMESTAMP "
        f"({_TYPES['TIMESTAMP']}); the driver reported {ts['type']} ({ts['typeName']!r})"
    )

    # --- VARCHAR type code: every string-shaped column reports java.sql.Types.VARCHAR, whether
    # it is bounded (a literal) or unbounded (a length-less CAST) -----------------------------
    for label in ("null_col", "string_col", "empty_col"):
        col = columns[label]
        assert col["type"] == _TYPES["VARCHAR"], (
            f"{label} must report java.sql.Types.VARCHAR ({_TYPES['VARCHAR']}); got {col['type']} "
            f"({col['typeName']!r})"
        )

    # --- typeName: the driver distinguishes the unbounded engine `string` type from a bounded
    # `varchar`, which is the underlying reason their precisions differ -----------------------
    assert columns["null_col"]["typeName"] == "string", (
        f"CAST(NULL AS VARCHAR) (no length declared) must report the unbounded engine typeName "
        f"'string'; got {columns['null_col']['typeName']!r}"
    )
    for label in ("string_col", "empty_col"):
        assert columns[label]["typeName"] == "varchar", (
            f"{label}: a VARCHAR literal must report the bounded engine typeName 'varchar', not "
            f"the unbounded 'string'; got {columns[label]['typeName']!r}"
        )

    # --- precision: bounded (a literal, sized to its own character count) vs unbounded (a
    # length-less CAST, which the driver reports as 2147483647) ------------------------------
    assert columns["null_col"]["precision"] == _UNBOUNDED_STRING_PRECISION, (
        f"CAST(NULL AS VARCHAR) declares no length, so AWS documents its reported precision as "
        f"{_UNBOUNDED_STRING_PRECISION} (the unbounded Athena `string` engine type); the driver "
        f"reported {columns['null_col']['precision']}"
    )
    assert columns["string_col"]["precision"] == len(_STRING_LITERAL), (
        f"a VARCHAR literal must report getPrecision() == its own character count "
        f"({len(_STRING_LITERAL)}), not the unbounded-string value "
        f"{_UNBOUNDED_STRING_PRECISION} — Trino types a string literal as a bounded varchar(n); "
        f"the driver reported {columns['string_col']['precision']} for {_STRING_LITERAL!r}"
    )
    assert columns["empty_col"]["precision"] == 0, (
        f"the empty string literal must report getPrecision() == 0 (its own character count), "
        f"got {columns['empty_col']['precision']}"
    )

    assert columns["int_col"]["type"] == _TYPES["INTEGER"], (
        f"int_col must report java.sql.Types.INTEGER ({_TYPES['INTEGER']}); got "
        f"{columns['int_col']['type']} ({columns['int_col']['typeName']!r})"
    )
    assert columns["bool_col"]["type"] == _TYPES["BOOLEAN"], (
        f"bool_col must report java.sql.Types.BOOLEAN ({_TYPES['BOOLEAN']}); got "
        f"{columns['bool_col']['type']} ({columns['bool_col']['typeName']!r})"
    )

    # Athena's ColumnInfo.Nullable is documented as always UNKNOWN, and every projected column
    # reports columnNullableUnknown(2), not columnNullable(1).
    for label, col in columns.items():
        assert col["nullable"] == _NULLABLE_CODE_UNKNOWN, (
            f"{label}: isNullable() must be columnNullableUnknown({_NULLABLE_CODE_UNKNOWN}) — "
            f"Athena reports ColumnInfo.Nullable UNKNOWN for every column, and the driver maps "
            f"that to columnNullableUnknown for every JDBC type this check projects; got "
            f"{col['nullable']}"
        )

    # --- the row: NULL and '' must stay apart ------------------------------------------------
    assert payload["rowCount"] == 1, f"expected exactly one row, got {payload['rowCount']}"
    cells = {label: payload["rows"][0][i] for i, label in enumerate(columns)}

    assert cells["dec_col"]["s"] == _DECIMAL_LITERAL, (
        f"the DECIMAL(38,9) round trip must be lossless over JDBC: expected "
        f"{_DECIMAL_LITERAL!r}, getString() gave {cells['dec_col']['s']!r}"
    )
    assert cells["ts_col"]["cls"] == "java.sql.Timestamp", (
        f"getObject() on a TIMESTAMP column must hand back a java.sql.Timestamp, not a text "
        f"stand-in; got {cells['ts_col']['cls']!r} for value {cells['ts_col']['s']!r}"
    )
    # Equality on the second-precision prefix, not `startswith`: an empty string starts every
    # string, so a `startswith` here would hold against a target that returned nothing.
    assert str(cells["ts_col"]["s"])[:19] == _TIMESTAMP_LITERAL[:19], (
        f"the TIMESTAMP must survive to the second: submitted "
        f"{_TIMESTAMP_LITERAL[:19]!r}, getString() gave {str(cells['ts_col']['s'])[:19]!r} "
        f"(full value {cells['ts_col']['s']!r})"
    )

    assert cells["null_col"]["null"] is True and cells["null_col"]["s"] is None, (
        f"CAST(NULL AS VARCHAR) must be SQL NULL over JDBC: wasNull() true and getString() null; "
        f"got wasNull={cells['null_col']['null']} getString={cells['null_col']['s']!r}"
    )
    assert cells["empty_col"]["null"] is False and cells["empty_col"]["s"] == "", (
        f"the empty string literal must NOT be NULL over JDBC: wasNull() false and getString() "
        f"''; got wasNull={cells['empty_col']['null']} getString={cells['empty_col']['s']!r}"
    )

    # --- the same execution over the API: the same distinction, in the API's own encoding ----
    qid = payload.get("queryExecutionId")
    assert qid, (
        f"the driver must report its execution id so the API leg reads the SAME execution; got "
        f"{qid!r} with error {payload.get('queryExecutionIdError')!r}"
    )
    api_rows = _api_data_rows(athena, qid)
    assert len(api_rows) == 1, f"expected one API data row for {qid}, got {len(api_rows)}"
    api = dict(zip(columns, api_rows[0]))
    assert api["null_col"] is None, (
        f"on the API wire a NULL Datum carries NO VarCharValue key, so null_col must read as "
        f"absent; GetQueryResults gave {api['null_col']!r}"
    )
    assert api["empty_col"] == "", (
        f"on the API wire the empty string is VarCharValue '', which is NOT the same as an absent "
        f"key; GetQueryResults gave {api['empty_col']!r}"
    )
    assert api["dec_col"] == cells["dec_col"]["s"], (
        f"the two transports must render the DECIMAL identically: api={api['dec_col']!r} "
        f"jdbc={cells['dec_col']['s']!r}"
    )
    assert api["ts_col"] == cells["ts_col"]["s"], (
        f"the two transports must render the TIMESTAMP identically: api={api['ts_col']!r} "
        f"jdbc={cells['ts_col']['s']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
