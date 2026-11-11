"""spark-created-glue-table-read-back-by-athena."""
from __future__ import annotations

import json
import random
import struct
import time
import uuid

from behavioral_harness import tags

CHECK = "spark-created-glue-table-read-back-by-athena"
GROUP = "data-plane"
SERVICES = ["athena", "emr-serverless", "glue", "s3"]

RELEASE_LABEL = "emr-7.9.0"

# A cold Spark job run on emr-7.9.0 does not fit in 300 s.
_JOB_BUDGET_S = 1200.0
_QUERY_BUDGET_S = 300.0
_APP_TEARDOWN_BUDGET_S = 420.0

_DATES = ("2026-02-01", "2026-02-02", "2026-02-03", "2026-02-04", "2026-02-05")
_REGIONS = ("eu-west", "us-east", "ap-south")
_ROWS_PER_DATE = 40

# Parquet physical types (parquet.thrift `Type`).
_PQ_INT64, _PQ_BYTE_ARRAY = 2, 6

# The job. Spark SQL writes a PARTITIONED Parquet table THROUGH the Glue Data Catalog acting as its
# Hive metastore, then computes its own aggregate over that table and parks it in S3 so the
# check can compare Spark's answer with Athena's over the same artifact.
_SPARK_JOB = '''\
import json
import sys

from pyspark.sql import SparkSession

facts_uri, db, tbl, warehouse_uri, answer_uri = sys.argv[1:6]

spark = SparkSession.builder.appName("sim2real-emrs-glue-ddl").enableHiveSupport().getOrCreate()

raw = spark.read.option("header", True).option("inferSchema", True).csv(facts_uri)
facts = raw.selectExpr(
    "cast(id as bigint) as id",
    "cast(region as string) as region",
    "cast(amount as bigint) as amount",
    "cast(dt as string) as dt",
)
facts.write.mode("overwrite").format("parquet").partitionBy("dt") \\
    .option("path", warehouse_uri).saveAsTable(db + "." + tbl)

rows = spark.sql(
    "SELECT dt, count(*) AS c, sum(amount) AS s FROM " + db + "." + tbl
    + " GROUP BY dt ORDER BY dt"
).collect()
payload = json.dumps([[str(r["dt"]), int(r["c"]), int(r["s"])] for r in rows])
spark.createDataFrame([(payload,)], ["payload"]).coalesce(1) \\
    .write.mode("overwrite").text(answer_uri)
spark.stop()
'''

_GLUE_ACTIONS = [
    "glue:GetDatabase", "glue:GetDatabases", "glue:CreateDatabase", "glue:CreateTable", "glue:GetTable",
    "glue:GetTables", "glue:UpdateTable", "glue:DeleteTable", "glue:CreatePartition",
    "glue:BatchCreatePartition", "glue:GetPartition", "glue:GetPartitions",
    "glue:UpdatePartition", "glue:BatchGetPartition",
]


# ===== stdlib Parquet footer reader (no pyarrow dependency) =====
class _TCompact:
    """Minimal Thrift compact-protocol reader — enough to decode a Parquet FileMetaData footer."""

    def __init__(self, buf: bytes) -> None:
        self.b = buf
        self.i = 0

    def _byte(self) -> int:
        v = self.b[self.i]
        self.i += 1
        return v

    def _varint(self) -> int:
        result = 0
        shift = 0
        while True:
            c = self._byte()
            result |= (c & 0x7F) << shift
            if not c & 0x80:
                return result
            shift += 7

    def _zigzag(self) -> int:
        n = self._varint()
        return (n >> 1) ^ -(n & 1)

    def _binary(self) -> bytes:
        n = self._varint()
        v = self.b[self.i:self.i + n]
        self.i += n
        return v

    def _value(self, t: int):
        if t == 1:
            return True
        if t == 2:
            return False
        if t == 3:
            return self._byte()
        if t in (4, 5, 6):
            return self._zigzag()
        if t == 7:
            v = struct.unpack_from("<d", self.b, self.i)[0]
            self.i += 8
            return v
        if t == 8:
            return self._binary()
        if t in (9, 10):
            return self._collection()
        if t == 11:
            return self._map()
        if t == 12:
            return self.struct()
        raise AssertionError(f"unknown thrift compact type {t} at offset {self.i}")

    def _collection(self) -> list:
        h = self._byte()
        size, et = h >> 4, h & 0x0F
        if size == 15:
            size = self._varint()
        return [self._value(et) for _ in range(size)]

    def _map(self) -> dict:
        size = self._varint()
        if size == 0:
            return {}
        h = self._byte()
        kt, vt = h >> 4, h & 0x0F
        return {self._value(kt): self._value(vt) for _ in range(size)}

    def struct(self) -> dict:
        out: dict[int, object] = {}
        fid = 0
        while True:
            h = self._byte()
            if h == 0:
                return out
            delta, t = h >> 4, h & 0x0F
            fid = fid + delta if delta else self._zigzag()
            out[fid] = self._value(t)


def _parquet_metadata(body: bytes) -> dict:
    assert len(body) > 12, f"object is {len(body)} bytes — too small to be a Parquet file"
    assert body[:4] == b"PAR1", f"missing leading PAR1 magic, got {body[:4]!r}"
    assert body[-4:] == b"PAR1", f"missing trailing PAR1 magic, got {body[-4:]!r}"
    footer_len = struct.unpack("<I", body[-8:-4])[0]
    start = len(body) - 8 - footer_len
    assert start >= 4, (
        f"declared footer length {footer_len} does not fit in a {len(body)}-byte object"
    )
    return _TCompact(body[start:len(body) - 8]).struct()


def _parquet_leaves(meta: dict) -> tuple[tuple[str, int], ...]:
    return tuple(
        (el[4].decode("utf-8"), el[1]) for el in meta[2] if 1 in el
    )


def _ensure_default_database(ctx, glue) -> None:
    """Pre-create the Glue `default` database, deleting it again only if this check created it.
    AWSCatalogMetastoreClient bootstraps `default` on init and is unusable if it cannot; creating
    it here keeps the job role's IAM surface to the actions under test."""
    from botocore.exceptions import ClientError

    try:
        glue.create_database(DatabaseInput={"Name": "default"})
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "AlreadyExistsException":
            raise
        return
    ctx.on_cleanup(lambda: glue.delete_database(Name="default"))


def _create_bucket(ctx, s3, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _purge_and_delete() -> None:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_purge_and_delete)


def _create_execution_role(ctx, iam, bucket: str) -> str:
    role_name = ctx.unique_name("sim2real-emrs-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "emr-serverless.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
                           "s3:GetBucketLocation", "s3:AbortMultipartUpload"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            # Enumerated, not glue:*, to keep the job role least-privilege.
            {"Effect": "Allow", "Action": _GLUE_ACTIONS, "Resource": "*"},
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-glue-s3", PolicyDocument=json.dumps(policy)
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-glue-s3")
    )
    # IAM exposes no condition to poll for "assumable by the service"; the bounded retry in
    # _start_job_run_with_retry (ClientError) and _run_job_to_terminal (FAILED with
    # "Could not assume runtime role") is what waits this out, not a fixed sleep here.
    return role_arn


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _start_job_run_with_retry(ctx, emrs, app_id: str, role_arn: str, job_driver: dict) -> str:
    from botocore.exceptions import ClientError

    driver = job_driver
    deadline = time.monotonic() + _budget_s(ctx, 180.0)
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return emrs.start_job_run(
                applicationId=app_id,
                clientToken=ctx.unique_name("sim2real-emrs-tok-"),
                executionRoleArn=role_arn,
                jobDriver=driver,
            )["jobRunId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError("StartJobRun succeeding past IAM propagation: the run budget ended "
                           "first; not graded")
    raise AssertionError(f"StartJobRun never succeeded after IAM propagation wait: {last_exc}")


def _await_job_run(emrs, app_id: str, job_run_id: str, budget_s: float, ctx=None) -> dict:
    terminal = {"SUCCESS", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"]
        if last["state"] in terminal:
            return last
        time.sleep(2)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"job run {job_run_id} reaching a terminal state: the run budget ended "
                           "first; not graded")
    raise AssertionError(
        f"job run {job_run_id} never reached a terminal state within {budget_s}s "
        f"(last state {last!r})"
    )


_ROLE_NOT_READY = "Could not assume runtime role"


def _run_job_to_terminal(ctx, emrs, app_id: str, role_arn: str, job_driver: dict,
                         budget_s: float) -> tuple[str, dict]:
    """Start a job run and wait for a terminal state, retrying ONLY the IAM-propagation failure:
    a new role can pass StartJobRun before EMR Serverless can assume it ("Could not assume
    runtime role"), and no API exposes that. Other failures go back to the caller to assert."""
    last = None
    for _ in range(5):
        job_run_id = _start_job_run_with_retry(ctx, emrs, app_id, role_arn, job_driver)
        last = _await_job_run(emrs, app_id, job_run_id, _budget_s(ctx, budget_s), ctx=ctx)
        if not (last["state"] == "FAILED"
                and _ROLE_NOT_READY in (last.get("stateDetails") or "")):
            return job_run_id, last
        time.sleep(2)
    raise AssertionError(
        f"execution role {role_arn} never became assumable by emr-serverless after 5 job runs: "
        f"{last!r}"
    )


def _teardown_application(emrs, app_id: str, budget_s: float) -> None:
    """Stop then DELETE the application, polling until the API says it is gone. Run inline because
    registered cleanups are time-bounded, and a slower delete would leak a billable application."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + budget_s
    try:
        emrs.stop_application(applicationId=app_id)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") == "ResourceNotFoundException":
            return
        # An application already CREATED, STOPPED or TERMINATED (deleted) refuses the stop.
        if not (err.get("Code") == "ValidationException"
                and "cannot be STOPPED" in (err.get("Message") or "")):
            raise
    while time.monotonic() < deadline:
        try:
            state = emrs.get_application(applicationId=app_id)["application"]["state"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if state == "TERMINATED":
            return
        if state in ("CREATED", "STOPPED"):
            break
        time.sleep(2)
    emrs.delete_application(applicationId=app_id)


def _list_keys(s3, bucket: str, prefix: str) -> list[str]:
    out = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        out.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(out)


def _all_partitions(glue, db: str, tbl: str) -> list[dict]:
    out = []
    for page in glue.get_paginator("get_partitions").paginate(DatabaseName=db, TableName=tbl):
        out.extend(page.get("Partitions", []))
    return out


def _athena_query(athena, sql: str, db: str, workgroup: str, budget_s: float,
                  ctx=None) -> dict:
    qid = athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={"Database": db},
        WorkGroup=workgroup,
    )["QueryExecutionId"]
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        if last["Status"]["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return last
        time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"Athena query {qid} reaching a terminal state: the run budget ended "
                           "first; not graded")
    raise AssertionError(
        f"Athena query {qid} never reached a terminal state within {budget_s}s (last={last!r})"
    )


def _athena_rows(athena, qid: str) -> tuple[list[dict], list[list[str | None]]]:
    """(ColumnInfo, data rows excluding the header row) for a finished query."""
    columns: list[dict] = []
    rows: list[list[str | None]] = []
    first = True
    for page in athena.get_paginator("get_query_results").paginate(QueryExecutionId=qid):
        if not columns:
            columns = page["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]
        page_rows = page["ResultSet"]["Rows"]
        if first:
            page_rows = page_rows[1:]  # Athena repeats the column names as row 0 of page 1
            first = False
        for r in page_rows:
            rows.append([c.get("VarCharValue") for c in r["Data"]])
    return columns, rows


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Spark on EMR Serverless writes a partitioned Parquet table through the Glue catalog; Glue
    must describe it as a Hive table with per-partition Locations and Athena must read the same
    rows. Deleting one catalog partition drops only its rows from Athena; its objects stay in S3.
    """
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    glue = ctx.client("glue")
    athena = ctx.client("athena")
    emrs = ctx.client("emr-serverless")

    bucket = ctx.unique_name("sim2real-emrs-cat-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    # --- seeded fixture: the expected aggregate comes from a per-run seed ---
    seed = uuid.uuid4().int & ((1 << 63) - 1)
    rng = random.Random(seed)
    expected: dict[str, list[int]] = {}
    lines = ["id,dt,region,amount"]
    row_id = 0
    for dt in _DATES:
        for _ in range(_ROWS_PER_DATE):
            region = _REGIONS[rng.randrange(len(_REGIONS))]
            amount = rng.randint(1, 99999)
            lines.append(f"{row_id},{dt},{region},{amount}")
            row_id += 1
            slot = expected.setdefault(dt, [0, 0])
            slot[0] += 1
            slot[1] += amount
    s3.put_object(
        Bucket=bucket, Key="input/facts.csv", Body=("\n".join(lines) + "\n").encode("utf-8")
    )
    s3.put_object(Bucket=bucket, Key="job/ddl.py", Body=_SPARK_JOB.encode("utf-8"))

    db_name = ctx.unique_name("sim2real_emrs_db_").lower().replace("-", "_")
    tbl_name = ctx.unique_name("sim2real_facts_").lower().replace("-", "_")
    _ensure_default_database(ctx, glue)
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    workgroup = ctx.unique_name("sim2real-emrs-wg-")
    athena.create_work_group(
        Name=workgroup,
        Configuration={
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/athena-results/"},
            "EnforceWorkGroupConfiguration": True,
        },
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=workgroup, RecursiveDeleteOption=True))

    role_arn = _create_execution_role(ctx, iam, bucket)

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-cat-app-"),
        releaseLabel=RELEASE_LABEL,
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
    )["applicationId"]
    ctx.on_cleanup(lambda: _teardown_application(emrs, app_id, 120.0))

    try:
        warehouse = f"s3://{bucket}/warehouse/{tbl_name}/"
        answer_uri = f"s3://{bucket}/spark-answer/"
        job_run_id, final = _run_job_to_terminal(
            ctx, emrs, app_id, role_arn,
            {"sparkSubmit": {
                "entryPoint": f"s3://{bucket}/job/ddl.py",
                "entryPointArguments": [
                    f"s3://{bucket}/input/facts.csv", db_name, tbl_name, warehouse, answer_uri,
                ],
                # Pin the metastore wiring explicitly instead of relying on the platform default.
                "sparkSubmitParameters": (
                    "--conf spark.driver.cores=2 --conf spark.driver.memory=4g "
                    "--conf spark.executor.cores=2 --conf spark.executor.memory=4g "
                    "--conf spark.executor.instances=2 "
                    "--conf spark.sql.catalogImplementation=hive "
                    "--conf spark.hadoop.hive.metastore.client.factory.class="
                    "com.amazonaws.glue.catalog.metastore.AWSGlueDataCatalogHiveClientFactory"
                ),
            }},
            _JOB_BUDGET_S,
        )
        assert final["state"] == "SUCCESS", (
            f"Spark job run {job_run_id} ended {final['state']!r}: {final.get('stateDetails')!r}"
        )

        # ---------- what Glue says Spark created ----------
        table = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"]
        sd = table["StorageDescriptor"]
        catalog_shape = {
            "serde": sd["SerdeInfo"].get("SerializationLibrary"),
            "input_format": sd.get("InputFormat"),
            "output_format": sd.get("OutputFormat"),
            "columns": [(c["Name"], c["Type"]) for c in sd["Columns"]],
            "partition_keys": [(k["Name"], k["Type"]) for k in table.get("PartitionKeys", [])],
            "table_type": table.get("TableType"),
            "location": sd.get("Location", "").rstrip("/"),
        }
        assert catalog_shape == {
            "serde": "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe",
            "input_format": "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat",
            "output_format": "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat",
            "columns": [("id", "bigint"), ("region", "string"), ("amount", "bigint")],
            "partition_keys": [("dt", "string")],
            "table_type": "EXTERNAL_TABLE",
            "location": f"s3://{bucket}/warehouse/{tbl_name}",
        }, (
            f"Spark's Glue catalog entry is not the Hive-shaped table a Parquet reader needs: "
            f"{catalog_shape!r}"
        )

        # ---------- partitions really registered, one per date, each at its own path ----------
        parts = _all_partitions(glue, db_name, tbl_name)
        got_values = sorted(p["Values"][0] for p in parts)
        assert got_values == sorted(_DATES), (
            f"registered partition values are {got_values!r}, expected exactly {sorted(_DATES)!r}"
        )
        misplaced = {
            p["Values"][0]: p["StorageDescriptor"]["Location"]
            for p in parts
            if not p["StorageDescriptor"]["Location"].rstrip("/").endswith(f"dt={p['Values'][0]}")
        }
        assert misplaced == {}, (
            f"partition Locations do not end in their own Hive-style directory: {misplaced!r}"
        )

        # ---------- the Parquet bytes themselves ----------
        warehouse_keys = _list_keys(s3, bucket, f"warehouse/{tbl_name}/")
        parquet_keys = [k for k in warehouse_keys if k.endswith(".parquet")]
        assert parquet_keys, f"no .parquet objects under the warehouse, keys were {warehouse_keys!r}"
        schemas = set()
        for key in parquet_keys:
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            schemas.add(_parquet_leaves(_parquet_metadata(body)))
        assert schemas == {
            (("id", _PQ_INT64), ("region", _PQ_BYTE_ARRAY), ("amount", _PQ_INT64))
        }, (
            f"Parquet leaf schemas are {sorted(schemas)!r}; expected exactly "
            f"id=INT64, region=BYTE_ARRAY, amount=INT64 with dt absent (partitionBy puts it in "
            f"the path, not the file)"
        )

        # ---------- Spark's own answer ----------
        answer_keys = [k for k in _list_keys(s3, bucket, "spark-answer/") if "/part-" in k]
        assert len(answer_keys) == 1, f"expected one spark-answer part, got {answer_keys!r}"
        spark_rows = json.loads(
            s3.get_object(Bucket=bucket, Key=answer_keys[0])["Body"].read().decode("utf-8").strip()
        )
        spark_agg = {r[0]: (int(r[1]), int(r[2])) for r in spark_rows}
        py_agg = {dt: (v[0], v[1]) for dt, v in expected.items()}
        assert spark_agg == py_agg, (
            f"Spark's aggregate over its own table is {spark_agg!r}, the Python expectation over the "
            f"seeded input is {py_agg!r}"
        )

        # ---------- Athena over the SAME artifact ----------
        sql = (
            f'SELECT dt, count(*) AS c, sum(amount) AS s FROM "{db_name}"."{tbl_name}" '
            f"GROUP BY dt ORDER BY dt"
        )
        qe = _athena_query(athena, sql, db_name, workgroup, _budget_s(ctx, _QUERY_BUDGET_S),
                           ctx=ctx)
        assert qe["Status"]["State"] == "SUCCEEDED", (
            f"Athena could not read the table Spark created: {qe['Status']!r}"
        )
        columns, rows = _athena_rows(athena, qe["QueryExecutionId"])
        athena_types = [(c["Name"], c["Type"]) for c in columns]
        assert athena_types == [("dt", "varchar"), ("c", "bigint"), ("s", "bigint")], (
            f"Athena's ResultSetMetadata types are {athena_types!r}; expected the Presto view of "
            f"the Hive types: varchar/bigint/bigint"
        )
        athena_agg = {r[0]: (int(r[1]), int(r[2])) for r in rows}
        assert athena_agg == py_agg, (
            f"Athena reads {athena_agg!r} from the table Spark wrote; Spark itself reported "
            f"{spark_agg!r} and the Python expectation is {py_agg!r} — three engines must agree on "
            f"one artifact"
        )

        # ---------- break exactly one thing: drop a partition from the CATALOG only ----------
        # An engine that lists the S3 prefix instead of calling GetPartitions keeps these rows.
        victim = _DATES[2]
        victim_keys = [k for k in parquet_keys if f"dt={victim}/" in k]
        assert victim_keys, f"no Parquet objects found for dt={victim} among {parquet_keys!r}"
        glue.delete_partition(DatabaseName=db_name, TableName=tbl_name, PartitionValues=[victim])

        qe2 = _athena_query(athena, sql, db_name, workgroup, _budget_s(ctx, _QUERY_BUDGET_S),
                            ctx=ctx)
        assert qe2["Status"]["State"] == "SUCCEEDED", (
            f"Athena failed after a partition was unregistered: {qe2['Status']!r}"
        )
        _, rows2 = _athena_rows(athena, qe2["QueryExecutionId"])
        after = {r[0]: (int(r[1]), int(r[2])) for r in rows2}
        assert set(after) == set(py_agg) - {victim}, (
            f"after delete_partition(dt={victim}) Athena still reports partitions {sorted(after)!r}; "
            f"expected {sorted(set(py_agg) - {victim})!r} — Athena is resolving data by listing S3 "
            f"instead of consulting the catalog"
        )
        assert sum(v[0] for v in after.values()) == sum(v[0] for v in py_agg.values()) - py_agg[victim][0], (
            f"row count after unregistering dt={victim} is {sum(v[0] for v in after.values())}, "
            f"expected the total minus exactly that partition's {py_agg[victim][0]} rows"
        )
        # effect-absent is about the CATALOG, not the data: the objects are untouched.
        still_in_s3 = [k for k in _list_keys(s3, bucket, f"warehouse/{tbl_name}/")
                       if f"dt={victim}/" in k and k.endswith(".parquet")]
        assert sorted(still_in_s3) == sorted(victim_keys), (
            f"unregistering the partition changed S3: now {sorted(still_in_s3)!r}, was "
            f"{sorted(victim_keys)!r} — the row must vanish because of the catalog, not the data"
        )

        # ---------- positive control: restoring the catalog entry restores the rows ----------
        glue.batch_create_partition(
            DatabaseName=db_name, TableName=tbl_name,
            PartitionInputList=[{
                "Values": [victim],
                "StorageDescriptor": {
                    **{k: v for k, v in sd.items() if k in
                       ("Columns", "InputFormat", "OutputFormat", "SerdeInfo", "Compressed")},
                    "Location": f"s3://{bucket}/warehouse/{tbl_name}/dt={victim}/",
                },
            }],
        )
        qe3 = _athena_query(athena, sql, db_name, workgroup, _budget_s(ctx, _QUERY_BUDGET_S),
                            ctx=ctx)
        assert qe3["Status"]["State"] == "SUCCEEDED", (
            f"Athena failed after the partition was restored: {qe3['Status']!r}"
        )
        _, rows3 = _athena_rows(athena, qe3["QueryExecutionId"])
        restored = {r[0]: (int(r[1]), int(r[2])) for r in rows3}
        assert restored == py_agg, (
            f"after batch_create_partition Athena reads {restored!r}, expected the full "
            f"{py_agg!r} — the catalog, and only the catalog, decided what was visible"
        )
    finally:
        _teardown_application(emrs, app_id, _APP_TEARDOWN_BUDGET_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
