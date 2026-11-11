"""jdbc-result-reuse-parameter-reaches-the-api-reuse-report."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path

from behavioral_harness import tags

CHECK = "jdbc-result-reuse-parameter-reaches-the-api-reuse-report"
GROUP = "query-execution"
SERVICES = ["athena"]

# The JDBC `EnableResultReuseByAge` / `MaxResultReuseAgeInMinutes` connection parameters
# (documented defaults FALSE and 60) map to StartQueryExecution's ResultReuseByAgeConfiguration.
# Reuse is keyed on the query text and the workgroup, so the marker is minted once and the
# negative leg uses a DIFFERENT marker. A query that requests reuse always gets
# Statistics.ResultReuseInformation back, even on its first run; one that does not may get none.

#: Pinned Athena JDBC 3.x uber jar. URL taken verbatim from the "JDBC driver uber jar" link on
#: https://docs.aws.amazon.com/athena/latest/ug/jdbc-v3-driver.html. The uber jar
#: is the one that bundles AthenaStreamingJavaClient, which is what speaks the port-444 streaming
#: service; the lean jar would need the dependency jars unzipped alongside it.
#: The `us-east-1` in the host below is the driver's fixed distribution CDN, not a resource
#: region — it is the same URL regardless of `ctx.region`, so it is not a hardcoded resource
#: region literal.
_JDBC_VERSION = "3.8.1"
_JDBC_JAR_URL = (
    "https://downloads.athena.us-east-1.amazonaws.com/drivers/JDBC/3.8.1/"
    "athena-jdbc-3.8.1-with-dependencies.jar"
)
_JAR_NAME = "athena-jdbc-3.8.1-with-dependencies.jar"
#: `com.amazon.athena.jdbc.AthenaDriver` per the "Driver class" section of
#: https://docs.aws.amazon.com/athena/latest/ug/jdbc-v3-driver-getting-started.html.
_DRIVER_CLASS_ENTRY = "com/amazon/athena/jdbc/AthenaDriver.class"
#: A JDK (not a JRE) because the probe is compiled in-container. Amazon Corretto rather than
#: eclipse-temurin: it is AWS-published on public.ecr.aws, so it does not depend on public.ecr.aws
#: mirroring a Docker Hub library image. The JDBC 3.x driver needs Java 8+
#: (https://docs.aws.amazon.com/athena/latest/ug/jdbc-v3-driver.html, System Requirements).
_JDK_IMAGE = "public.ecr.aws/amazoncorretto/amazoncorretto:21"
#: Emitted by the Java probe so the check can find its one JSON line among SLF4J/driver noise.
_SENTINEL = "__SIM2REAL_JSON__"

#: javac + JVM start + one Athena query in the runner's pre-seeded JDK image.
_JAVA_TIMEOUT_S = 600.0
#: Where the runner provides the pinned driver jar (~25 MB), a runner prerequisite like the image.
_JAR_PATH = Path.home() / ".cache" / "sim2real" / _JAR_NAME


def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object, then the bucket. Athena writes `<qid>.csv`, `<qid>.csv.metadata` and
    `<qid>.txt` into the output location, so DeleteBucket alone would fail. No bare
    `except Exception`: a teardown that cannot finish must surface rather than leak silently."""
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
    """Poll GetQueryExecution to a REQUIRED terminal state with a bounded deadline.

    300s and not the 30-90s some athena checks use: a query over a real EXTERNAL TABLE additionally
    pays Glue metadata resolution, split planning and S3 listing, and the account's query queue is
    shared. A bare time.sleep would not be an assertion; timing out here is a hard failure.
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
    """Fully-qualified table name for a DML (SELECT/EXECUTE) statement.

    Athena parses DDL with the Hive parser, which quotes identifiers with BACKTICKS, but parses DML
    with the Trino parser, which quotes them with DOUBLE QUOTES. A backtick inside a SELECT makes
    the statement unclassifiable and StartQueryExecution refuses it SYNCHRONOUSLY with
    `InvalidRequestException: Queries of this type are not supported`. So the DDL below
    keeps its backticks and every DML statement goes through here.
    """
    return f'"{database}"."{table}"'


def _api_data_rows(athena, qid):
    """Every GetQueryResults data row for *qid* as a list of lists of str-or-None, header dropped.

    NULL and the empty string are DIFFERENT on this wire: a NULL Datum carries NO `VarCharValue`
    key at all, an empty string carries `VarCharValue: ""`. `.get("VarCharValue")` therefore maps
    NULL to None and "" to "". Pages are
    concatenated so a multi-page result is compared in full.
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
    """Fail as ``tool_missing`` when the runner lacks the driver jar or the JDK image.

    Both are runner prerequisites: the check never downloads the jar or pulls the image, so no run
    egresses to a host other than its target. The jar is verified STRUCTURALLY (over 20 MB, a zip,
    holding the driver class entry) rather than by checksum, because AWS publishes no checksum for
    it; a jar that fails that is the runner's fault too, never a finding about the target.
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
    """The pinned driver jar the runner provides, checked by ``_require_jdbc_prerequisites``."""
    return _JAR_PATH


def _jdbc_workspace(ctx):
    """A private temp dir holding the driver jar, the credential env-file and the Java probe.

    Mode 0700 and removed at teardown: it holds the leased session credentials, which the runner
    passes per-harness and never through the ambient environment.
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
    """The JDBC 3.x connection properties for THIS target.

    Every name here was read off the DRIVER, not off the docs:
    `AthenaDriver().getPropertyInfo("jdbc:athena://", new Properties())` on the pinned 3.8.1 jar
    lists 85 properties, and the workgroup one is spelled `WorkGroup` with a capital G. The sample
    application in jdbc-v3-driver-getting-started.html spells it `Workgroup`, which is NOT in that
    list — a driver 3.x connection property the driver does not recognise is not an error, so
    trusting the doc would have sent every query below to the `primary` workgroup and made the
    marker correlation (and therefore several of these checks) assert nothing. `Region`,
    `OutputLocation`, `Catalog`, `Database`, `CredentialsProvider`, `AthenaEndpoint`,
    `AthenaStreamingEndpoint`, `S3Endpoint`, `ResultFetcher`, `FetchSize`, `EnableResultReuseByAge`,
    `MaxResultReuseAgeInMinutes` and `ConnectionTest` were all confirmed present verbatim in the
    same list.

    The `CredentialsProvider=DefaultChain` value is from the sample application in
    https://docs.aws.amazon.com/athena/latest/ug/jdbc-v3-driver-getting-started.html. The endpoint
    properties are the documented `AthenaEndpoint` / `AthenaStreamingEndpoint` / `S3Endpoint`
    parameters (jdbc-v3-driver-advanced-connection-parameters.html); only the streaming one is
    set, since the driver's SDK reads the others from the environment ctx.subprocess_env() gives.
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

    `--network host` so the same command reaches athena.<region>.amazonaws.com:443/:444 on real AWS
    and a loopback emulator endpoint on an emulator; it is a transport pin, not a branch. The SQL
    goes through a FILE rather than argv so no quoting rule of the shell or of Java can alter the
    statement the engine is asked to run.
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

#: One JDBC probe, shared by every check in this family: connect, run /w/probe.sql, and print one
#: JSON line describing the ResultSetMetaData and every cell (value, wasNull, runtime class). argv
#: is (fetchSize, queryTimeoutSeconds); 0 means "leave the JDBC default alone".
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
    """Stand up the cheapest real Athena data source: one CSV object in S3 registered as a typed
    EXTERNAL TABLE. Returns (database, table, data_bucket, data_bytes).

    Cleanups are registered at creation time and the runner runs them LIFO, so the registration
    order (results bucket -> data bucket -> DROP DATABASE CASCADE) tears down as DROP DATABASE ->
    data bucket -> results bucket. DROP DATABASE is itself an Athena query, so the results bucket
    must outlive it -- which LIFO guarantees.
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
    """A dedicated workgroup, so ListQueryExecutions returns only THIS check's executions.

    RecursiveDeleteOption=True on teardown: a workgroup that has run a query cannot be deleted
    without it, and a DeleteWorkGroup that fails leaves a named resource behind.
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

    This is how a JDBC-submitted query is correlated back to the API without trusting the driver's
    own id: the marker is a unique literal the check put in the SQL, and the workgroup is private
    to this check. ListQueryExecutions is eventually consistent right after submission, so the
    lookup is a BOUNDED retry that raises -- never a sleep, never a silent empty result.
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


_CSV_ROWS = "1,alpha\n2,bravo\n3,charlie\n"
_COLUMNS = "`id` int, `name` string"
#: The driver's documented default for MaxResultReuseAgeInMinutes
#: (jdbc-v3-driver-advanced-connection-parameters.html) and the API's documented default for
#: ResultReuseByAgeConfiguration.MaxAgeInMinutes (com.amazonaws.athena#ResultReuseByAgeConfiguration:
#: "The default is 60") — the same number on both transports, which is itself the point.
_REUSE_MINUTES = 60
#: Sequential reuse measured non-deterministic on the first attempt for the concurrent sibling, so
#: the reuse leg retries a bounded number of times before failing. Each attempt is a full query.
_REUSE_ATTEMPTS = 3


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """The JDBC `EnableResultReuseByAge` parameter reaches Athena's ResultReuseConfiguration: a
    JDBC-submitted rerun is reported as a reuse by the API, scans 0 bytes, and returns the same rows
    — and with the parameter at its documented default it does not."""
    from fidelity_tests_runner import require_tools

    require_tools("docker")
    _require_jdbc_prerequisites()

    athena = ctx.client("athena")
    out = _output_location(ctx)
    workgroup = _workgroup(ctx, athena, out)
    database, table, _, _ = _external_table(ctx, athena, out, _CSV_ROWS, _COLUMNS)

    ws = _jdbc_workspace(ctx)
    reuse_props = {
        "WorkGroup": workgroup,
        "EnableResultReuseByAge": "TRUE",
        "MaxResultReuseAgeInMinutes": str(_REUSE_MINUTES),
    }

    # Reuse is keyed on the query TEXT, so the marker is minted once and reused verbatim.
    marker = ctx.unique_name("mk")
    sql = (
        f"SELECT id, name, '{marker}' AS marker FROM {_dml_name(database, table)} ORDER BY id"
    )
    expected = [
        ["1", "alpha", marker],
        ["2", "bravo", marker],
        ["3", "charlie", marker],
    ]

    def jdbc_run(props, statement):
        payload = _run_java(
            ctx,
            ws,
            "Probe",
            _PROBE_JAVA,
            args=(0, 0),
            props=_driver_properties(ctx, out, database=database, extra=props),
            sql=statement,
        )
        assert payload.get("ok") is True, (
            f"the JDBC run must succeed; the driver reported {str(payload)[:300]}"
        )
        qid = payload.get("queryExecutionId")
        assert qid, (
            f"the driver must report its execution id so the reuse report can be read for THAT "
            f"execution; got {qid!r} with error {payload.get('queryExecutionIdError')!r}"
        )
        return payload, qid

    def reuse_report(qid):
        execution = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        assert execution["Status"]["State"] == "SUCCEEDED", (
            f"execution {qid} must be SUCCEEDED before its reuse report means anything; it is "
            f"{execution['Status']['State']!r}: "
            f"{execution['Status'].get('StateChangeReason')!r}"
        )
        # ResultReuseInformation lives inside Statistics, not on QueryExecution directly.
        info = execution["Statistics"].get("ResultReuseInformation") or {}
        return execution, info

    # ---- leg 1: the first JDBC run populates the cache and is NOT itself a reuse -------------
    first_payload, first_qid = jdbc_run(reuse_props, sql)
    assert _jdbc_rows(first_payload) == expected, (
        f"the first JDBC run must return the table's rows in ORDER BY id order; got "
        f"{_jdbc_rows(first_payload)}"
    )
    first_execution, first_info = reuse_report(first_qid)
    # A query that REQUESTS reuse always gets Statistics.ResultReuseInformation back, even on
    # its own first (non-reused) run, so an absent struct here is a real failure.
    assert first_info, (
        f"a query that requested reuse must report Statistics.ResultReuseInformation even on its "
        f"first run; execution {first_qid} reported none"
    )
    assert first_info.get("ReusedPreviousResult") is False, (
        f"the FIRST run of a never-seen query cannot be a reuse, even with reuse enabled: "
        f"execution {first_qid} reported ReusedPreviousResult "
        f"{first_info.get('ReusedPreviousResult')!r}"
    )
    first_scanned = first_execution["Statistics"]["DataScannedInBytes"]
    assert first_scanned > 0, (
        f"the first run must really scan the data, or a 0-byte second run proves nothing: "
        f"DataScannedInBytes was {first_scanned} for {first_qid}"
    )

    # ---- leg 2: an identical JDBC rerun IS reported as a reuse, and scans nothing ------------
    attempts = []
    reused_qid = None
    for _ in range(_REUSE_ATTEMPTS):
        payload, qid = jdbc_run(reuse_props, sql)
        execution, info = reuse_report(qid)
        assert info, (
            f"reuse was requested for {qid} (same as the first run's connection shape), so "
            f"Statistics.ResultReuseInformation must be present; it was absent"
        )
        attempts.append((qid, info.get("ReusedPreviousResult"),
                         execution["Statistics"]["DataScannedInBytes"]))
        assert qid != first_qid, (
            f"a reuse is still a NEW execution id that merely serves an old result; the driver "
            f"returned the first id {first_qid} again"
        )
        assert _jdbc_rows(payload) == expected, (
            f"a reused result must still be the SAME rows: got {_jdbc_rows(payload)} for {qid}"
        )
        if info.get("ReusedPreviousResult") is True:
            reused_qid = qid
            assert execution["Statistics"]["DataScannedInBytes"] == 0, (
                f"a reused execution scans nothing, which is the whole economic point: {qid} "
                f"reported DataScannedInBytes "
                f"{execution['Statistics']['DataScannedInBytes']}"
            )
            break
    assert reused_qid, (
        f"with EnableResultReuseByAge=TRUE and MaxResultReuseAgeInMinutes={_REUSE_MINUTES}, an "
        f"identical JDBC rerun must be reported as a reuse within {_REUSE_ATTEMPTS} sequential "
        f"attempts; the attempts were (qid, ReusedPreviousResult, scanned) = {attempts}"
    )

    # ---- leg 3: the documented DEFAULT (reuse off) must NOT reuse ----------------------------
    # A different marker, so this leg cannot accidentally hit the entry leg 2 just proved exists;
    # the point is that the same CONNECTION shape with reuse off runs fresh.
    off_marker = ctx.unique_name("off")
    off_sql = (
        f"SELECT id, name, '{off_marker}' AS marker FROM {_dml_name(database, table)} ORDER BY id"
    )
    off_props = {"WorkGroup": workgroup}
    _, off_first_qid = jdbc_run(off_props, off_sql)
    _, off_second_qid = jdbc_run(off_props, off_sql)
    off_execution, off_info = reuse_report(off_second_qid)
    assert off_second_qid != off_first_qid, (
        f"two runs must be two executions; both reported {off_first_qid}"
    )
    assert off_info.get("ReusedPreviousResult") is not True, (
        f"EnableResultReuseByAge defaults to FALSE, so an identical rerun over a connection that "
        f"does not set it must run FRESH; execution {off_second_qid} reported "
        f"ReusedPreviousResult {off_info.get('ReusedPreviousResult')!r} -- the driver is enabling "
        f"reuse the client never asked for"
    )
    assert off_execution["Statistics"]["DataScannedInBytes"] > 0, (
        f"a fresh execution must scan the data; {off_second_qid} reported DataScannedInBytes "
        f"{off_execution['Statistics']['DataScannedInBytes']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
