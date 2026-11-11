"""glue-etl-job-writes-parquet-to-s3-positive."""
from __future__ import annotations

import json
import textwrap
import time

from behavioral_harness import tags

CHECK = "glue-etl-job-writes-parquet-to-s3-positive"
GROUP = "resource-binding"
SERVICES = ["emr", "glue", "s3"]

_ROW_COUNT = 5

_SCRIPT = textwrap.dedent(
    """\
    import sys
    from awsglue.utils import getResolvedOptions
    from awsglue.context import GlueContext
    from pyspark.context import SparkContext

    args = getResolvedOptions(sys.argv, ["JOB_NAME", "SOURCE_PATH", "OUTPUT_PATH"])
    sc = SparkContext()
    glue_context = GlueContext(sc)

    dyf = glue_context.create_dynamic_frame.from_options(
        connection_type="s3",
        format="csv",
        connection_options={"paths": [args["SOURCE_PATH"]], "recurse": True},
        format_options={"withHeader": True},
        transformation_ctx="datasource0",
    )
    df = dyf.toDF().coalesce(1)
    df.write.mode("overwrite").parquet(args["OUTPUT_PATH"])
    """
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue ETL job writes its transformed output as a valid Parquet dataset to S3."""
    bucket = _create_bucket(ctx)
    rows = "\n".join(f"{i},name-{i},{i * 1.5}" for i in range(_ROW_COUNT))
    _put_object(ctx, bucket, "data/input.csv", "id,name,amount\n" + rows + "\n")
    _put_object(ctx, bucket, "scripts/write_parquet.py", _SCRIPT)

    role_arn = _create_glue_role(
        ctx,
        extra_statements=[
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    )

    glue = ctx.client("glue")
    job_name = ctx.unique_name("sim2real-glue-job-")
    glue.create_job(
        Name=job_name,
        Role=role_arn,
        Command={
            "Name": "glueetl",
            "ScriptLocation": f"s3://{bucket}/scripts/write_parquet.py",
            "PythonVersion": "3",
        },
        GlueVersion="4.0",
        WorkerType="G.1X",
        NumberOfWorkers=2,
        MaxRetries=0,
        Timeout=15,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))

    output_prefix = "output/parquet-test/"
    job_run = _run_job_to_terminal(
        glue,
        job_name,
        {
            "--SOURCE_PATH": f"s3://{bucket}/data/input.csv",
            "--OUTPUT_PATH": f"s3://{bucket}/{output_prefix}",
        },
        timeout_s=900,
    )
    assert job_run["JobRunState"] == "SUCCEEDED", job_run.get("ErrorMessage")
    assert job_run.get("ExecutionTime", 0) > 0, (
        f"ExecutionTime was {job_run.get('ExecutionTime')!r} for a SUCCEEDED run, so no Spark "
        f"compute was billed and nothing actually ran"
    )

    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=output_prefix)
    keys = [o["Key"] for o in resp.get("Contents", [])]
    parquet_keys = [k for k in keys if k.endswith(".parquet")]
    # Glue's default S3-optimized committer (Glue 3.0+) writes the part file directly and
    # never a Hadoop-style "_SUCCESS" marker -- so completion is proven by the part file's own
    # content (PAR1 magic, row/column round-trip), not by a marker Glue does not produce.
    assert keys == parquet_keys, f"unexpected object(s) under {output_prefix!r}: {keys}"
    assert len(parquet_keys) == 1, f"expected exactly one parquet part file, got {keys}"

    body = s3.get_object(Bucket=bucket, Key=parquet_keys[0])["Body"].read()
    # Parquet files start and end with the 4-byte magic number "PAR1".
    assert body[:4] == b"PAR1" and body[-4:] == b"PAR1", "output is not a valid Parquet file"

    try:
        import io

        import pyarrow.parquet as pq

        table = pq.read_table(io.BytesIO(body))
        assert table.num_rows == _ROW_COUNT, table.num_rows
        assert set(table.column_names) == {"id", "name", "amount"}, table.column_names
    except ImportError:
        pass  # pyarrow unavailable: the magic-number structural check above still holds


# ===== helpers =====

def _bucket_region_kwargs(ctx):
    if ctx.region == "us-east-1":
        return {}
    return {"CreateBucketConfiguration": {"LocationConstraint": ctx.region}}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-s3-")
    s3.create_bucket(Bucket=name, **_bucket_region_kwargs(ctx))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _put_object(ctx, bucket: str, key: str, body) -> None:
    if isinstance(body, str):
        body = body.encode("utf-8")
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=body)


def _create_glue_role(ctx, extra_statements=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))

    if extra_statements:
        policy_name = ctx.unique_name("sim2real-glue-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


_TERMINAL_JOB_STATES = {"SUCCEEDED", "FAILED", "TIMEOUT", "ERROR", "STOPPED"}


def _run_job_to_terminal(glue, job_name: str, arguments: dict, *, timeout_s: float = 900.0):
    """Start the job and poll to a terminal state, retrying the IAM-propagation failure.

    Glue reports "Role ... should be given assume role permissions for Glue Service" as a
    FAILED job *run* about 5s in, not as a StartJobRun error, and no API reports that the role
    has become assumable -- so the bounded retry has to be on the terminal run state, not a
    fixed pre-sleep before the first attempt. StartJobRun can also itself reject a concurrent
    attempt (the account or job's own run-concurrency limit) while an earlier attempt is still
    winding down; that is a request-level retry, not a role-propagation one.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    job_run: dict = {}
    while time.monotonic() < deadline:
        try:
            run_id = glue.start_job_run(JobName=job_name, Arguments=arguments)["JobRunId"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConcurrentRunsExceededException":
                raise
            time.sleep(5)
            continue
        while time.monotonic() < deadline:
            job_run = glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]
            if job_run["JobRunState"] in _TERMINAL_JOB_STATES:
                break
            time.sleep(2)
        if job_run.get("JobRunState") != "FAILED":
            return job_run
        if "assume role permissions" not in (job_run.get("ErrorMessage") or ""):
            return job_run
        time.sleep(2)
    raise AssertionError(
        f"job {job_name} did not reach a non-role-propagation terminal state within {timeout_s}s"
        f" (last: {job_run!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
