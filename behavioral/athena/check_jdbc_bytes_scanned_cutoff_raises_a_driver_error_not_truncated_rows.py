"""jdbc-bytes-scanned-cutoff-raises-a-driver-error-not-truncated-rows."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path

from behavioral_harness import tags

CHECK = "jdbc-bytes-scanned-cutoff-raises-a-driver-error-not-truncated-rows"
GROUP = "workgroup"
SERVICES = ["athena"]

#: Pinned Athena JDBC 3.x uber jar (https://docs.aws.amazon.com/athena/latest/ug/jdbc-v3-driver.html);
#: it bundles the port-444 streaming client. The us-east-1 host serves the download for every region.
_JDBC_VERSION = "3.8.1"
_JDBC_JAR_URL = (
    "https://downloads.athena.us-east-1.amazonaws.com/drivers/JDBC/3.8.1/"
    "athena-jdbc-3.8.1-with-dependencies.jar"
)
_JAR_NAME = "athena-jdbc-3.8.1-with-dependencies.jar"
#: `com.amazon.athena.jdbc.AthenaDriver` per the "Driver class" section of
#: https://docs.aws.amazon.com/athena/latest/ug/jdbc-v3-driver-getting-started.html.
_DRIVER_CLASS_ENTRY = "com/amazon/athena/jdbc/AthenaDriver.class"
#: A JDK (not a JRE) because the probe is compiled in-container; the driver needs Java 8+.
_JDK_IMAGE = "public.ecr.aws/amazoncorretto/amazoncorretto:21"
#: Emitted by the Java probe so the check can find its one JSON line among SLF4J/driver noise.
_SENTINEL = "__SIM2REAL_JSON__"

#: javac + JVM start + one Athena query in the pre-seeded JDK image.
_JAVA_TIMEOUT_S = 600.0
#: Where the pinned driver jar (~25 MB) is pre-seeded, like the JDK image.
_JAR_PATH = Path.home() / ".cache" / "sim2real" / _JAR_NAME


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object, then the bucket; Athena writes several result files per query."""
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
    """Poll GetQueryExecution to a terminal state; raise on timeout.

    300s because an external-table query also pays Glue resolution, split planning and S3 listing.
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
    """Fully-qualified table name for a DML statement.

    Athena parses DML with Trino (double quotes); a backtick in a SELECT is refused.
    """
    return f'"{database}"."{table}"'


def _api_data_rows(athena, qid):
    """Every GetQueryResults data row for *qid* as lists of str-or-None, header dropped.

    A NULL Datum carries no VarCharValue key, so NULL maps to None and "" stays "".
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
    """Raise RequiredToolMissing when the driver jar or the JDK image is not pre-seeded.

    The jar is checked structurally (size, zip, driver class) because AWS publishes no checksum.
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
    """A private (0700) temp dir holding the driver jar, the credential env-file and the probe."""
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

    Endpoints follow ctx.subprocess_env().
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
    # --pull never: the JDK image is pre-seeded and never pulled.
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith(_SENTINEL)]
    assert len(lines) == 1, (
        f"the JDBC probe must print exactly one {_SENTINEL} line; got {len(lines)} "
        f"(rc={proc.returncode}) stderr_tail={proc.stderr[-400:]!r} "
        f"stdout_tail={proc.stdout[-200:]!r}"
    )
    return json.loads(lines[0][len(_SENTINEL) :])

#: JDBC probe: run /w/probe.sql and print one JSON line with the metadata and every cell.
#: argv is (fetchSize, queryTimeoutSeconds); 0 leaves the JDBC default.
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


def _external_table(ctx, athena, out, rows_csv, columns):
    """One CSV object in S3 registered as an EXTERNAL TABLE; returns (db, table, bucket, bytes).

    LIFO cleanup drops the database (itself a query) before the results bucket goes.
    """
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


def _workgroup(ctx, athena, out, configuration=None):
    """A dedicated workgroup, so ListQueryExecutions returns only this check's executions.

    RecursiveDeleteOption=True: a workgroup that has run a query cannot be deleted without it.
    """
    name = ctx.unique_name("sim2real-athena-jdbc-wg-")
    config = {"ResultConfiguration": {"OutputLocation": out}}
    config.update(configuration or {})
    ctx.on_cleanup(
        lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)
    )
    athena.create_work_group(
        Name=name,
        Configuration=config,
        Tags=[
            {"Key": "sim2real", "Value": CHECK[:250]},
            {"Key": "sim2real:managed", "Value": "true"},
        ],
    )
    return name


def _execution_for_marker(athena, workgroup, marker, *, timeout_s=120.0, interval_s=3.0):
    """The one QueryExecution in *workgroup* whose QueryString carries *marker*.

    ListQueryExecutions is eventually consistent after submission, so this retries, bounded.
    """
    deadline = time.monotonic() + timeout_s
    seen = 0
    while time.monotonic() < deadline:
        ids = athena.list_query_executions(WorkGroup=workgroup).get("QueryExecutionIds", [])
        seen = len(ids)
        if ids:
            details = athena.batch_get_query_execution(QueryExecutionIds=ids)["QueryExecutions"]
            hits = [d for d in details if marker in d.get("Query", "")]
            if len(hits) == 1:
                return hits[0]
            assert len(hits) < 2, (
                f"marker {marker!r} must identify exactly one execution in workgroup "
                f"{workgroup}; it matched {len(hits)}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"no QueryExecution in workgroup {workgroup} carried the marker {marker!r} within "
        f"{timeout_s}s ({seen} executions listed) -- the JDBC submission never reached Athena"
    )


#: Athena's smallest accepted BytesScannedCutoffPerQuery: 10,000,000 bytes, not 10 MiB.
_CUTOFF_BYTES = 10000000
#: ~14.9 MB of CSV (rows average ~24.8 bytes), comfortably above the cutoff.
_PAYLOAD_ROWS = 600000
_COLUMNS = "`id` int, `name` string"
#: Bounded wait for the control's result object, whose latency calibrates the absence window.
_RESULT_OBJECT_TIMEOUT_S = 120.0
#: Cap on the calibrated absence window: the hold is min(max(3 x measured latency, 30), 90) seconds.
_ABSENCE_HOLD_CAP = 90.0
_ABSENCE_HOLD_FLOOR = 30.0


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """A workgroup bytes-scanned cutoff makes a JDBC query raise with no rows delivered; Athena
    records it CANCELLED with the bytes-limit reason and writes no result. Lifting the cutoff
    restores the query.
    """
    from fidelity_tests_runner import require_tools

    require_tools("docker")
    _require_jdbc_prerequisites()

    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    prefix = "results/"
    out = f"s3://{results_bucket}/{prefix}"

    rows_csv = "".join(f"{i},name-{i:012d}\n" for i in range(_PAYLOAD_ROWS))
    payload_bytes = len(rows_csv.encode())
    assert payload_bytes > _CUTOFF_BYTES, (
        f"the scan fodder must exceed the cutoff this check exists to trip: built "
        f"{payload_bytes} bytes against a {_CUTOFF_BYTES}-byte cutoff"
    )
    database, table, _, _ = _external_table(ctx, athena, out, rows_csv, _COLUMNS)

    # Two workgroups, identical but for the cutoff, so the cutoff is the ONLY difference.
    open_wg = _workgroup(ctx, athena, out)
    capped_wg = _workgroup(ctx, athena, out, {"BytesScannedCutoffPerQuery": _CUTOFF_BYTES})
    capped = athena.get_work_group(WorkGroup=capped_wg)["WorkGroup"]["Configuration"]
    assert capped.get("BytesScannedCutoffPerQuery") == _CUTOFF_BYTES, (
        f"the capped workgroup must really carry the cutoff before anything is concluded from it: "
        f"GetWorkGroup reported {capped.get('BytesScannedCutoffPerQuery')!r}"
    )

    # A full scan: no LIMIT, and an aggregate so the engine cannot answer from metadata.
    def sql_for(marker):
        return (
            f"SELECT count(*) AS n, max(name) AS mx, '{marker}' AS marker "
            f"FROM {_dml_name(database, table)}"
        )

    def jdbc_run(work_group, marker):
        return _run_java(
            ctx,
            ws,
            "Probe",
            _PROBE_JAVA,
            args=(0, 0),
            props=_driver_properties(
                ctx, out, database=database, extra={"WorkGroup": work_group}
            ),
            sql=sql_for(marker),
        )

    ws = _jdbc_workspace(ctx)

    # ---- beat 1, positive control, over the same transport -----------------------------------
    control_marker = ctx.unique_name("ctl")
    control = jdbc_run(open_wg, control_marker)
    assert control.get("ok") is True, (
        f"positive control: the identical SQL over JDBC in a workgroup with NO cutoff must succeed, "
        f"so the refusal below is attributable to the cutoff; the driver reported "
        f"{str(control)[:300]}"
    )
    control_rows = _jdbc_rows(control)
    assert control_rows == [[str(_PAYLOAD_ROWS), f"name-{_PAYLOAD_ROWS - 1:012d}", control_marker]], (
        f"positive control: the uncapped scan must count all {_PAYLOAD_ROWS} rows; it returned "
        f"{control_rows}"
    )
    control_execution = _execution_for_marker(athena, open_wg, control_marker)
    control_scanned = control_execution["Statistics"]["DataScannedInBytes"]
    assert control_scanned > _CUTOFF_BYTES, (
        f"positive control: the uncapped query must actually scan more than the cutoff, or the "
        f"capped query would have nothing to trip; it scanned {control_scanned} against "
        f"{_CUTOFF_BYTES}"
    )
    # The latency the absence window below is calibrated against.
    object_latency = _result_object_latency_s(
        s3, results_bucket, prefix, control_execution["QueryExecutionId"]
    )

    # ---- beat 2, the negative: one thing changed, the workgroup's cutoff ----------------------
    marker = ctx.unique_name("mk")
    capped_payload = jdbc_run(capped_wg, marker)
    assert capped_payload.get("ok") is False, (
        f"a {_CUTOFF_BYTES}-byte cutoff must reach the JDBC client as a thrown exception, never as "
        f"rows: the probe returned ok={capped_payload.get('ok')} with "
        f"rowCount={capped_payload.get('rowCount')} rows={_jdbc_rows(capped_payload)[:2]}"
    )
    assert capped_payload.get("rowsBeforeError") == 0, (
        f"a refused query must deliver NO rows at all, not a truncated set: the driver handed over "
        f"{capped_payload.get('rowsBeforeError')} rows before raising, which is silent truncation "
        f"-- the exact failure this check exists to catch"
    )

    # ---- beat 3, identity of the refusal, read at the destination -----------------------------
    execution = _execution_for_marker(athena, capped_wg, marker)
    qid = execution["QueryExecutionId"]
    status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
    reason = status.get("StateChangeReason") or ""
    # A bytes-scanned-cutoff abort terminates CANCELLED, never FAILED.
    assert status["State"] == "CANCELLED", (
        f"the capped execution {qid} must end CANCELLED (the state real AWS actually uses for a "
        f"bytes-scanned-cutoff abort, per the sibling cutoff check's own measurement), not "
        f"{status['State']!r} ({reason!r})"
    )
    assert reason == "Bytes scanned limit was exceeded", (
        f"Athena must attribute the abort to the bytes-scanned limit with its exact documented "
        f"reason text; StateChangeReason for {qid} was {reason!r} (driver said "
        f"{str(capped_payload.get('causeChain'))[:150]!r})"
    )
    scanned = execution["Statistics"]["DataScannedInBytes"]
    assert scanned <= payload_bytes, (
        f"the aborted query cannot have scanned more than the whole object: DataScannedInBytes "
        f"{scanned} against {payload_bytes} bytes of data"
    )

    # ---- beat 4, the effect is absent, on TWO observables, over a calibrated window -----------
    hold = min(max(3 * object_latency, _ABSENCE_HOLD_FLOOR), _ABSENCE_HOLD_CAP)
    _assert_no_result_object(s3, results_bucket, prefix, qid, hold)
    code = _error_code(
        lambda: athena.get_query_results(QueryExecutionId=qid),
        f"GetQueryResults on the aborted execution {qid}",
    )
    assert code == "InvalidRequestException", (
        f"an aborted execution must refuse GetQueryResults with InvalidRequestException (the code "
        f"behavioral/athena/check_get_query_results_rejects_failed_query.py asserts); got {code!r}"
    )

    # ---- beat 5, RESTORE: remove the cutoff and the identical JDBC call succeeds again ---------
    # The restore separates "the cutoff blocked this query" from "this workgroup blocks everything".
    athena.update_work_group(
        WorkGroup=capped_wg,
        ConfigurationUpdates={"RemoveBytesScannedCutoffPerQuery": True},
    )
    lifted = athena.get_work_group(WorkGroup=capped_wg)["WorkGroup"]["Configuration"]
    assert "BytesScannedCutoffPerQuery" not in lifted, (
        f"RemoveBytesScannedCutoffPerQuery must actually clear the field before the restore leg "
        f"means anything; GetWorkGroup still reports "
        f"{lifted.get('BytesScannedCutoffPerQuery')!r}"
    )
    restored_marker = ctx.unique_name("res")
    restored = jdbc_run(capped_wg, restored_marker)
    assert restored.get("ok") is True, (
        f"restore: with the cutoff removed, the IDENTICAL JDBC call in the SAME workgroup must "
        f"succeed -- otherwise the refusal above was the workgroup, not the cutoff; the driver "
        f"reported {str(restored)[:300]}"
    )
    restored_rows = _jdbc_rows(restored)
    assert restored_rows == [
        [str(_PAYLOAD_ROWS), f"name-{_PAYLOAD_ROWS - 1:012d}", restored_marker]
    ], f"restore: the uncapped scan must count all {_PAYLOAD_ROWS} rows; it returned {restored_rows}"


def _result_keys(s3, bucket, prefix, qid):
    """Every object key under *prefix* that belongs to execution *qid* (matched by id)."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []) if qid in o["Key"])
    return sorted(keys)


def _result_object_latency_s(s3, bucket, prefix, qid, timeout_s=_RESULT_OBJECT_TIMEOUT_S):
    """Seconds until the result object for a SUCCEEDED *qid* becomes listable; raises if never.

    The 0.5s floor keeps a fast target from producing a zero-length absence hold.
    """
    started = time.monotonic()
    deadline = started + timeout_s
    while time.monotonic() < deadline:
        if _result_keys(s3, bucket, prefix, qid):
            return max(time.monotonic() - started, 0.5)
        time.sleep(2.0)
    raise AssertionError(
        f"a SUCCEEDED query must write its result object under {prefix}: nothing containing {qid} "
        f"was listable within {timeout_s}s, so the absence assertion has no control to calibrate "
        f"against and this check cannot conclude anything"
    )


def _assert_no_result_object(s3, bucket, prefix, qid, hold):
    """Hold the absence of *qid*'s result object for *hold* seconds, re-listing throughout."""
    deadline = time.monotonic() + hold
    reads = 0
    while time.monotonic() < deadline:
        keys = _result_keys(s3, bucket, prefix, qid)
        reads += 1
        assert not keys, (
            f"an aborted execution must leave no result object under {prefix}; read {reads} of the "
            f"{hold:.0f}s absence window found {keys} for {qid}"
        )
        time.sleep(2.0)
    assert reads >= 2, (
        f"the absence window must contain at least two independent listings to be a freeze "
        f"detector; it managed {reads} in {hold:.0f}s"
    )


def _error_code(call, what):
    """The AWS error code *call* raises; an unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = call()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"{what} must be refused; it succeeded and returned {str(result)[:200]}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
