"""spark-saveastable-without-glue-createtable-permission-is-denied."""
from __future__ import annotations

import gzip
import json
import random
import time
import uuid

from behavioral_harness import tags

CHECK = "spark-saveastable-without-glue-createtable-permission-is-denied"
GROUP = "negative-classes"
SERVICES = ["athena", "emr-serverless", "glue", "s3"]

RELEASE_LABEL = "emr-7.9.0"

# Two Spark job runs do not fit in 300 s.
_JOB_BUDGET_S = 900.0
_LOG_BUDGET_S = 420.0
_QUERY_BUDGET_S = 300.0
_APP_TEARDOWN_BUDGET_S = 420.0

_DATES = ("2026-03-01", "2026-03-02", "2026-03-03")
_ROWS_PER_DATE = 30

# Every Glue action the metastore client needs to write a partitioned table, split at the ONE action
# this check removes. Enumerated rather than glue:*, so the removal is the only difference.
_GLUE_READ_WRITE = [
    "glue:GetDatabase", "glue:GetDatabases", "glue:CreateDatabase", "glue:GetTable", "glue:GetTables",
    "glue:UpdateTable", "glue:DeleteTable", "glue:CreatePartition",
    "glue:BatchCreatePartition", "glue:GetPartition", "glue:GetPartitions",
    "glue:UpdatePartition", "glue:BatchGetPartition", "glue:DeletePartition",
]
_GLUE_CREATE_TABLE = "glue:CreateTable"

_SPARK_JOB = '''\
import sys

from pyspark.sql import SparkSession

facts_uri, db, tbl, warehouse_uri = sys.argv[1:5]

spark = SparkSession.builder.appName("sim2real-emrs-glue-denied").enableHiveSupport().getOrCreate()

raw = spark.read.option("header", True).option("inferSchema", True).csv(facts_uri)
facts = raw.selectExpr(
    "cast(id as bigint) as id",
    "cast(amount as bigint) as amount",
    "cast(dt as string) as dt",
)
facts.write.mode("overwrite").format("parquet").partitionBy("dt") \\
    .option("path", warehouse_uri).saveAsTable(db + "." + tbl)
spark.stop()
'''


def _error(fn) -> tuple[str, str]:
    """The AWS error ``(code, message)`` a call raised. Raises if the call SUCCEEDS, since an
    unexpected success means the backend accepted what AWS refuses."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(
        f"the call was expected to be refused but SUCCEEDED, returning {result!r}"
    )


def _ensure_default_database(ctx, glue) -> None:
    """Pre-create the Glue `default` database, deleting it again only if this check created it.
    AWSCatalogMetastoreClient bootstraps `default` on init and is unusable if it cannot; creating
    it here keeps the job role's IAM surface to the actions under test."""
    from botocore.exceptions import ClientError

    try:
        glue.create_database(DatabaseInput={"Name": "default"}, Tags={"sim2real": "true"})
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
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]}
    )

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


def _create_execution_role(ctx, iam, bucket: str, glue_actions: list[str], label: str) -> str:
    role_name = ctx.unique_name(f"sim2real-emrs-{label}-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "emr-serverless.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
            {"Effect": "Allow", "Action": glue_actions, "Resource": "*"},
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-glue-s3", PolicyDocument=json.dumps(policy)
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-glue-s3")
    )
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

    deadline = time.monotonic() + _budget_s(ctx, 180.0)
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return emrs.start_job_run(
                applicationId=app_id,
                clientToken=ctx.unique_name("sim2real-emrs-tok-"),
                executionRoleArn=role_arn,
                jobDriver=job_driver,
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


def _await_driver_stderr(s3, bucket: str, log_prefix: str, app_id: str, job_run_id: str,
                         budget_s: float, ctx=None) -> tuple[str, bytes]:
    want = f"{log_prefix}applications/{app_id}/jobs/{job_run_id}/SPARK_DRIVER/stderr.gz"
    deadline = time.monotonic() + budget_s
    seen: list[str] = []
    while time.monotonic() < deadline:
        seen = _list_keys(s3, bucket, f"{log_prefix}applications/{app_id}/jobs/{job_run_id}/")
        if want in seen:
            body = s3.get_object(Bucket=bucket, Key=want)["Body"].read()
            if body:
                return want, body
        time.sleep(2)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"a non-empty {want!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"no non-empty {want!r} appeared within {budget_s}s; keys under the job's log prefix were "
        f"{seen!r}"
    )


def _all_tables(glue, db: str) -> list[str]:
    out = []
    for page in glue.get_paginator("get_tables").paginate(DatabaseName=db):
        out.extend(t["Name"] for t in page.get("TableList", []))
    return sorted(out)


def _athena_scalar_row(athena, sql: str, db: str, workgroup: str,
                       budget_s: float, ctx=None) -> list[str | None]:
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
            break
        time.sleep(1)
    else:
        if ctx is not None and _budget_spent(ctx):
            raise TimeoutError(f"Athena query {qid} terminating: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"Athena query {qid} never terminated within {budget_s}s")
    assert last["Status"]["State"] == "SUCCEEDED", (
        f"Athena query {qid} ended {last['Status']!r}"
    )
    rows = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]["Rows"]
    assert len(rows) == 2, f"expected a header row plus one data row, got {rows!r}"
    return [c.get("VarCharValue") for c in rows[1]["Data"]]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Without `glue:CreateTable` a Spark saveAsTable job FAILS, the table is absent from Glue and
    the driver stderr names AccessDeniedException; a role differing only by that action succeeds
    and its partitioned table is readable by Athena with the seeded row count and sum.
    """
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    glue = ctx.client("glue")
    athena = ctx.client("athena")
    emrs = ctx.client("emr-serverless")

    bucket = ctx.unique_name("sim2real-emrs-deny-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    seed = uuid.uuid4().int & ((1 << 63) - 1)
    rng = random.Random(seed)
    lines = ["id,dt,amount"]
    total_rows = 0
    total_amount = 0
    row_id = 0
    for dt in _DATES:
        for _ in range(_ROWS_PER_DATE):
            amount = rng.randint(1, 99999)
            lines.append(f"{row_id},{dt},{amount}")
            row_id += 1
            total_rows += 1
            total_amount += amount
    s3.put_object(
        Bucket=bucket, Key="input/facts.csv", Body=("\n".join(lines) + "\n").encode("utf-8")
    )
    s3.put_object(Bucket=bucket, Key="job/ddl.py", Body=_SPARK_JOB.encode("utf-8"))

    db_name = ctx.unique_name("sim2real_deny_db_").lower().replace("-", "_")
    tbl_name = ctx.unique_name("sim2real_facts_").lower().replace("-", "_")
    _ensure_default_database(ctx, glue)
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    workgroup = ctx.unique_name("sim2real-emrs-deny-wg-")
    athena.create_work_group(
        Name=workgroup,
        Configuration={
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/athena-results/"},
            "EnforceWorkGroupConfiguration": True,
        },
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: athena.delete_work_group(WorkGroup=workgroup, RecursiveDeleteOption=True)
    )

    denied_role = _create_execution_role(ctx, iam, bucket, list(_GLUE_READ_WRITE), "deny")
    allowed_role = _create_execution_role(
        ctx, iam, bucket, list(_GLUE_READ_WRITE) + [_GLUE_CREATE_TABLE], "allow"
    )
    # IAM exposes no condition to poll for "assumable by the service", so there is nothing to wait
    # on here directly. _run_job_to_terminal's bounded retry (5 attempts, 30s apart) is the actual
    # wait for IAM propagation: it already tolerates a role rejected as not-yet-assumable.

    log_prefix = "logs/"
    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-deny-app-"),
        releaseLabel=RELEASE_LABEL,
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        monitoringConfiguration={
            "s3MonitoringConfiguration": {"logUri": f"s3://{bucket}/{log_prefix}"}
        },
        tags={"sim2real": "true"},
    )["applicationId"]
    ctx.on_cleanup(lambda: _teardown_application(emrs, app_id, 120.0))

    try:
        warehouse = f"s3://{bucket}/warehouse/{tbl_name}/"
        driver = {"sparkSubmit": {
            "entryPoint": f"s3://{bucket}/job/ddl.py",
            "entryPointArguments": [
                f"s3://{bucket}/input/facts.csv", db_name, tbl_name, warehouse,
            ],
            "sparkSubmitParameters": (
                "--conf spark.driver.cores=1 --conf spark.driver.memory=2g "
                "--conf spark.executor.cores=1 --conf spark.executor.memory=2g "
                "--conf spark.executor.instances=1 "
                "--conf spark.sql.catalogImplementation=hive "
                "--conf spark.hadoop.hive.metastore.client.factory.class="
                "com.amazonaws.glue.catalog.metastore.AWSGlueDataCatalogHiveClientFactory"
            ),
        }}

        # ---------- break exactly one thing: remove glue:CreateTable ----------
        bad_run, bad_final = _run_job_to_terminal(
            ctx, emrs, app_id, denied_role, driver, _JOB_BUDGET_S
        )
        assert bad_final["state"] == "FAILED", (
            f"saveAsTable ran to {bad_final['state']!r} with an execution role that lacks "
            f"{_GLUE_CREATE_TABLE!r}, expected FAILED — the backend registered a catalog entry real "
            f"AWS refuses ({bad_final.get('stateDetails')!r})"
        )

        # effect-absent, in the catalog: the table was never created.
        code, message = _error(lambda: glue.get_table(DatabaseName=db_name, Name=tbl_name))
        assert code == "EntityNotFoundException", (
            f"glue.get_table for the denied table raised {code!r}, expected "
            f"'EntityNotFoundException' — the entry must not exist at all"
        )
        assert message == "Entity Not Found", (
            f"glue.get_table for the denied table said {message!r}, expected 'Entity Not Found'"
        )
        listed = _all_tables(glue, db_name)
        assert listed == [], (
            f"the database lists tables after the denied run: {listed!r}"
        )

        # the refusal is legible where an operator would look for it.
        log_key, log_gz = _await_driver_stderr(
            s3, bucket, log_prefix, app_id, bad_run, _budget_s(ctx, _LOG_BUDGET_S), ctx=ctx
        )
        assert log_gz[:2] == b"\x1f\x8b", (
            f"{log_key!r} does not start with the gzip magic, got {log_gz[:2]!r}"
        )
        stderr_text = gzip.decompress(log_gz).decode("utf-8", errors="replace")
        assert "AccessDeniedException" in stderr_text, (
            f"the driver log for the denied run does not name AccessDeniedException "
            f"(tail: {stderr_text[-800:]!r})"
        )
        assert _GLUE_CREATE_TABLE in stderr_text, (
            f"the driver log does not name the denied action {_GLUE_CREATE_TABLE!r}, so the refusal "
            f"cannot be attributed to it (tail: {stderr_text[-800:]!r})"
        )

        # ---------- positive control: change only the role ----------
        _, ok_final = _run_job_to_terminal(
            ctx, emrs, app_id, allowed_role, driver, _JOB_BUDGET_S
        )
        assert ok_final["state"] == "SUCCESS", (
            f"the same job with {_GLUE_CREATE_TABLE!r} granted ended {ok_final['state']!r}: "
            f"{ok_final.get('stateDetails')!r} — without this the denial above proves nothing"
        )
        table = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"]
        keys = [(k["Name"], k["Type"]) for k in table.get("PartitionKeys", [])]
        assert keys == [("dt", "string")], (
            f"the control run's table has PartitionKeys {keys!r}, expected [('dt', 'string')]"
        )
        row = _athena_scalar_row(
            athena,
            f'SELECT count(*) AS c, sum(amount) AS s FROM "{db_name}"."{tbl_name}"',
            db_name, workgroup, _budget_s(ctx, _QUERY_BUDGET_S), ctx=ctx,
        )
        assert (int(row[0]), int(row[1])) == (total_rows, total_amount), (
            f"Athena reads {row!r} from the control table; the seeded input has "
            f"{(total_rows, total_amount)!r}"
        )
    finally:
        _teardown_application(emrs, app_id, _APP_TEARDOWN_BUDGET_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
