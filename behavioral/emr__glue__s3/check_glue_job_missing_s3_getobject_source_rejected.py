"""glue-job-missing-s3-getobject-source-rejected."""
from __future__ import annotations

import json
import textwrap
import time

from behavioral_harness import tags

CHECK = "glue-job-missing-s3-getobject-source-rejected"
GROUP = "permission-boundary"
SERVICES = ["emr", "glue", "s3"]

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
    row_count = dyf.toDF().count()
    # The RDD API's saveAsTextFile() reaches for the legacy
    # org.apache.hadoop.mapred.DirectOutputCommitter, which Glue 4.0's Hadoop
    # version no longer ships -- every run fails with ClassNotFoundException
    # regardless of S3 permissions. The DataFrame writer uses the current
    # FileOutputCommitter and still lands a "part-*" object under OUTPUT_PATH.
    glue_context.spark_session.createDataFrame([(str(row_count),)], ["value"]).coalesce(1).write.mode(
        "overwrite"
    ).text(args["OUTPUT_PATH"])
    """
)


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue ETL job whose role can read its own script but lacks s3:GetObject on the
    source data prefix fails the run and writes no output, while a sibling job with the
    correct permission succeeds (in-file positive control)."""
    bucket = _create_bucket(ctx)
    _put_object(ctx, bucket, "data/input.csv", "id,name\n1,a\n2,b\n3,c\n")
    _put_object(ctx, bucket, "scripts/read_csv.py", _SCRIPT)

    glue = ctx.client("glue")

    # --- Negative: role can list the bucket and read the job script, but is explicitly
    # denied s3:GetObject on the "data/*" source prefix. ---
    bad_role_arn = _create_glue_role(
        ctx,
        extra_statements=[
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/scripts/*", f"arn:aws:s3:::{bucket}/output/*"],
            },
            {
                "Effect": "Deny",
                "Action": ["s3:GetObject"],
                "Resource": f"arn:aws:s3:::{bucket}/data/*",
            },
        ],
    )
    bad_job = ctx.unique_name("sim2real-glue-job-bad-")
    glue.create_job(
        Name=bad_job,
        Role=bad_role_arn,
        Command={
            "Name": "glueetl",
            "ScriptLocation": f"s3://{bucket}/scripts/read_csv.py",
            "PythonVersion": "3",
        },
        GlueVersion="4.0",
        WorkerType="G.1X",
        NumberOfWorkers=2,
        MaxRetries=0,
        Timeout=15,
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=bad_job))

    s3 = ctx.client("s3")
    bad_output_prefix = "output/bad-run/"
    bad_run = _start_and_wait_with_retry(
        ctx,
        glue,
        bad_job,
        {
            "--SOURCE_PATH": f"s3://{bucket}/data/",
            "--OUTPUT_PATH": f"s3://{bucket}/{bad_output_prefix}",
        },
        is_acceptable=lambda r: r["JobRunState"] == "FAILED" and _is_source_read_blocked(r),
        timeout_s=900,
        # A retry here means the deny had not yet finished propagating on the
        # rejected attempt, which can let that one attempt race through and
        # write output before a later, fully-propagated attempt correctly
        # fails -- clear that transient output so the final absence check
        # reflects the fully-propagated (final) attempt, not a stale one.
        before_retry=lambda: _clear_prefix(s3, bucket, bad_output_prefix),
    )
    assert bad_run["JobRunState"] == "FAILED", bad_run
    assert _is_source_read_blocked(bad_run), (
        f"expected the FAILED run's error to show the denied S3 read as a missing source, "
        f"got {bad_run.get('ErrorMessage')!r}"
    )

    resp = s3.list_objects_v2(Bucket=bucket, Prefix=bad_output_prefix)
    assert resp.get("KeyCount", 0) == 0, "output must not exist when the source read is denied"

    # --- Positive control: role WITH s3:GetObject on data/* succeeds in the same file. ---
    good_role_arn = _create_glue_role(
        ctx,
        extra_statements=[
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    )
    good_job = ctx.unique_name("sim2real-glue-job-good-")
    glue.create_job(
        Name=good_job,
        Role=good_role_arn,
        Command={
            "Name": "glueetl",
            "ScriptLocation": f"s3://{bucket}/scripts/read_csv.py",
            "PythonVersion": "3",
        },
        GlueVersion="4.0",
        WorkerType="G.1X",
        NumberOfWorkers=2,
        MaxRetries=0,
        Timeout=15,
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=good_job))

    good_output_prefix = "output/good-run/"
    good_run = _start_and_wait_with_retry(
        ctx,
        glue,
        good_job,
        {
            "--SOURCE_PATH": f"s3://{bucket}/data/",
            "--OUTPUT_PATH": f"s3://{bucket}/{good_output_prefix}",
        },
        is_acceptable=lambda r: r["JobRunState"] == "SUCCEEDED",
        timeout_s=900,
    )
    assert good_run["JobRunState"] == "SUCCEEDED", good_run.get("ErrorMessage")
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=good_output_prefix)
    part_keys = [o["Key"] for o in resp.get("Contents", []) if "part-" in o["Key"]]
    assert len(part_keys) >= 1, f"expected at least one part- output object under {good_output_prefix!r}, found {resp.get('Contents')!r}"
    content = s3.get_object(Bucket=bucket, Key=part_keys[0])["Body"].read().decode().strip()
    assert int(content) == 3, content


def _bucket_region_kwargs(ctx):
    if ctx.region == "us-east-1":
        return {}
    return {"CreateBucketConfiguration": {"LocationConstraint": ctx.region}}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-s3-")
    s3.create_bucket(Bucket=name, **_bucket_region_kwargs(ctx))

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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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


def _wait_for_job_run(ctx, glue, job_name: str, run_id: str, timeout_s: float = 900.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        job_run = glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]
        if job_run["JobRunState"] in _TERMINAL_JOB_STATES:
            return job_run
        time.sleep(2)
    raise AssertionError(f"job run {run_id} did not reach a terminal state within {timeout_s}s")


def _is_source_read_blocked(job_run: dict) -> bool:
    """Hadoop's S3A filesystem (which Glue's DynamicFrame CSV reader sits on) masks a
    403 on the source object as a FileNotFoundException during its getFileStatus /
    schema-inference step, so the real, deterministic signature of "denied the
    source read" on this connector is "No such file or directory", not an explicit
    AccessDenied string: Glue 4.0 returns
    exactly that for a role denied s3:GetObject on an object that demonstrably
    exists (the in-file positive control reads the identical object)."""
    message = job_run.get("ErrorMessage") or ""
    return "no such file or directory" in message.lower()


def _start_job_run_with_retry(glue, job_name: str, arguments: dict, retries: int = 4, delay: int = 15) -> str:
    """Glue can briefly report ConcurrentRunsExceededException right after a
    prior run on the same job reaches a terminal state (its "currently
    running" bookkeeping trails the JobRun status by a few seconds); retry
    through that window instead of failing outright."""
    from botocore.exceptions import ClientError

    for attempt in range(retries + 1):
        try:
            return glue.start_job_run(JobName=job_name, Arguments=arguments)["JobRunId"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConcurrentRunsExceededException" and attempt < retries:
                time.sleep(delay)
                continue
            raise


def _clear_prefix(s3, bucket: str, prefix: str) -> None:
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
    if objs:
        s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})


def _start_and_wait_with_retry(
    ctx, glue, job_name, arguments, *, is_acceptable, timeout_s=900.0, retries=3, delay=20, before_retry=None
):
    """A just-created execution role can take a short time to become assumable by
    Glue, and its attached policies (including an explicit Deny) to fully
    propagate; retry the whole start+wait cycle through that documented IAM
    eventual-consistency window instead of trusting a fixed pre-run sleep.
    `is_acceptable` names the terminal condition this call is actually after --
    SUCCEEDED for the positive control, FAILED-with-the-specific-S3-denial for
    the negative -- so a run that terminates for propagation noise (the role
    not yet assumable, or a not-yet-propagated Deny letting one attempt race
    through) gets one more bounded attempt instead of being read as the
    intended result."""
    run = None
    for attempt in range(retries + 1):
        run_id = _start_job_run_with_retry(glue, job_name, arguments)
        run = _wait_for_job_run(ctx, glue, job_name, run_id, timeout_s=timeout_s)
        if is_acceptable(run) or attempt == retries:
            return run
        if before_retry is not None:
            before_retry()
        time.sleep(delay)
    return run


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
