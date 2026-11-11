"""glue-spark-etl-job-converts-csv-to-parquet-preserving-every-row."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "glue-spark-etl-job-converts-csv-to-parquet-preserving-every-row"
GROUP = 'jobs'
SERVICES = ['glue', 's3']

_ROWS = 200
_CSV = b"id,name,score\n" + b"".join(
    f"{i},name{i},{i}.5\n".encode() for i in range(1, _ROWS + 1))
# sum(1..200)
_ID_SUM = _ROWS * (_ROWS + 1) // 2

# A real Spark job: read the CSV, write Parquet, then RE-READ the Parquet it just wrote and
# report what came back. The marker is derived from the written objects, not from the input,
# so it cannot be produced without a working Parquet writer AND reader.
_SCRIPT = b"""import sys
import boto3
from awsglue.utils import getResolvedOptions
from pyspark.sql import SparkSession
from pyspark.sql.functions import col
from pyspark.sql.functions import sum as sum_

args = getResolvedOptions(sys.argv, ['INPUT', 'OUTPUT', 'MARKER'])
spark = SparkSession.builder.getOrCreate()
source = spark.read.option('header', 'true').csv(args['INPUT'])
source.coalesce(1).write.mode('overwrite').parquet(args['OUTPUT'])
back = spark.read.parquet(args['OUTPUT'])
rows = back.count()
total = back.select(sum_(col('id').cast('long'))).collect()[0][0]
columns = ','.join(back.columns)
bucket, key = args['MARKER'][len('s3://'):].split('/', 1)
boto3.client('s3').put_object(
    Bucket=bucket, Key=key, Body=f'{rows}|{total}|{columns}'.encode())
"""


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """A Spark ETL job converts a CSV to genuine Parquet (PAR1 magic at both ends): re-reading the
    output yields the same 200 rows, id sum and three columns."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    output_prefix = "parquet/"
    marker_key = "marker/reread.txt"

    bucket = ctx.unique_name("sim2real-behav-gluespark-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real",
                                                             "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="scripts/etl.py", Body=_SCRIPT)
    s3.put_object(Bucket=bucket, Key="input/rows.csv", Body=_CSV)

    role_arn = _create_glue_role(ctx, iam, bucket, write=True)

    job = ctx.unique_name("sim2real-behav-gluespark-")
    glue.create_job(
        Name=job, Role=role_arn,
        Command={"Name": "glueetl", "PythonVersion": "3",
                 "ScriptLocation": f"s3://{bucket}/scripts/etl.py"},
        GlueVersion="4.0", WorkerType="G.1X", NumberOfWorkers=2,
        ExecutionProperty={"MaxConcurrentRuns": 5},
        DefaultArguments={"--TempDir": f"s3://{bucket}/tmp/"},
        Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_job(JobName=job),
                                         f"glue job {job}"))

    job_run = _run_job_to_terminal(glue, job, {
        "--INPUT": f"s3://{bucket}/input/rows.csv",
        "--OUTPUT": f"s3://{bucket}/{output_prefix}",
        "--MARKER": f"s3://{bucket}/{marker_key}"})

    assert job_run["JobRunState"] == "SUCCEEDED", (
        f"job run ended {job_run['JobRunState']!r}: {job_run.get('ErrorMessage')!r}"
    )
    assert job_run["ExecutionTime"] > 0, (
        f"ExecutionTime was {job_run['ExecutionTime']!r} for a SUCCEEDED run, so no Spark "
        f"compute was billed and nothing actually ran"
    )

    written = _list_keys(s3, bucket, output_prefix)
    part_keys = [k for k in written if k.endswith(".parquet")]
    assert part_keys, (
        f"no Parquet object under {output_prefix!r} after a SUCCEEDED run; the prefix holds "
        f"{written!r}"
    )
    bodies = [_get_object(s3, bucket, k) for k in part_keys]
    magic = [(b[:4], b[-4:]) for b in bodies]
    assert all(head == b"PAR1" and tail == b"PAR1" for head, tail in magic), (
        f"a part file is not a Parquet file; head/tail pairs were {magic!r}"
    )
    assert not any(b.startswith(b"id,") for b in bodies), (
        f"a part file still looks like the input CSV: {bodies[0][:40]!r}"
    )

    marker = _get_object(s3, bucket, marker_key)
    assert marker is not None, (
        f"the job wrote no marker at {marker_key!r}, so it never re-read its own output"
    )
    expected_marker = f"{_ROWS}|{_ID_SUM}|id,name,score".encode()
    assert marker.strip() == expected_marker, (
        f"re-reading the written Parquet produced {marker!r}, expected {expected_marker!r} "
        f"(rows|sum(id)|columns)"
    )
    assert _get_object(s3, bucket, "input/rows.csv") == _CSV, (
        f"the input object was modified by the run; it must be read-only to the job"
    )


# ===== helpers =====

def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _create_glue_role(ctx, iam, bucket: str, *, write: bool) -> str:
    """Create a role Glue can assume, with read (and optionally write) on one bucket."""
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Principal": {"Service": "glue.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]})
    role = ctx.unique_name("sim2real-behav-gluerole-")
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: iam.delete_role(RoleName=role),
                                         f"iam role {role}"))
    managed = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role, PolicyArn=managed)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.detach_role_policy(RoleName=role, PolicyArn=managed),
        f"detach {managed} from {role}"))
    actions = ["s3:GetObject", "s3:PutObject"] if write else ["s3:GetObject"]
    iam.put_role_policy(RoleName=role, PolicyName="sim2real-s3", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions,
                       "Resource": f"arn:aws:s3:::{bucket}/*"},
                      {"Effect": "Allow", "Action": ["s3:ListBucket"],
                       "Resource": f"arn:aws:s3:::{bucket}"}]}))
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.delete_role_policy(RoleName=role, PolicyName="sim2real-s3"),
        f"inline policy on {role}"))
    return arn


def _run_job_to_terminal(glue, job: str, arguments: dict, *, timeout_s: float = 600.0) -> dict:
    """Start the job and poll to a terminal state, retrying the IAM-propagation failure.

    Glue reports "Role ... should be given assume role permissions for Glue Service" as a
    FAILED job *run* about 5s in, not as a StartJobRun error, and no API reports that the
    role has become assumable -- so the bounded retry has to be on the terminal run state.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    record: dict = {}
    while time.monotonic() < deadline:
        try:
            run_id = glue.start_job_run(JobName=job, Arguments=arguments)["JobRunId"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConcurrentRunsExceededException":
                raise
            time.sleep(5)
            continue
        while time.monotonic() < deadline:
            record = glue.get_job_run(JobName=job, RunId=run_id)["JobRun"]
            if record["JobRunState"] in ("SUCCEEDED", "FAILED", "STOPPED", "ERROR",
                                         "TIMEOUT"):
                break
            time.sleep(5)
        if record.get("JobRunState") != "FAILED":
            return record
        if "assume role permissions" not in (record.get("ErrorMessage") or ""):
            return record
        time.sleep(2)
    return record


def _get_object(s3, bucket: str, key: str):
    from botocore.exceptions import ClientError
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchKey":
            return None
        raise


def _list_keys(s3, bucket: str, prefix: str) -> list:
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _retry_delete(fn: Callable[[], Any], label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions:
    a throttled or dependency-blocked delete would leak silently while the check passes."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "NoSuchEntity", "NoSuchBucket",
            "ResourceNotFoundException", "404")
    transient = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                 "OperationTimeoutException", "ConcurrentModificationException",
                 "DeleteConflict", "InvalidInputException", "RequestLimitExceeded")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in transient or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)
        except Exception as exc:  # noqa: BLE001 - re-raised
            raise RuntimeError(f"{label}: {type(exc).__name__}: {exc}") from exc


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    from botocore.exceptions import ClientError

    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise
        return
    _retry_delete(lambda: s3.delete_bucket(Bucket=bucket), f"s3 bucket {bucket}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
