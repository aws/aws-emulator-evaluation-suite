"""spark-calculation-returns-computed-stdout-result."""
from __future__ import annotations

import json
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "spark-calculation-returns-computed-stdout-result"
GROUP = 'query-execution'
SERVICES = ['athena']


# An IDLE session bills DPU-hours until reclaimed; the shortest accepted idle timeout is a
# backstop if cleanup never runs.
_SESSION_IDLE_TIMEOUT_MIN = 5

# sum(1..100), computed by a Spark range/groupBy rather than appearing as a literal in the code.
_EXPECTED_SUM = "5050"


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object, including the session's stdout/stderr/results, then the bucket."""
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "spark-calculation-returns-computed-stdout"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _split_s3_uri(uri):
    """(bucket, key) from an s3:// URI."""
    p = urllib.parse.urlparse(uri)
    assert p.scheme == "s3", f"not an s3 URI: {uri!r}"
    assert p.netloc, f"s3 URI has no bucket: {uri!r}"
    return p.netloc, p.path.lstrip("/")


def _spark_execution_role(ctx, bucket):
    """The IAM role Athena assumes to run Spark, scoped to this run's bucket.

    CreateWorkGroup for the PySpark engine is refused without an ExecutionRole.
    """
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    role = ctx.unique_name("sim2real-behav-athena-spark-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "athena.amazonaws.com"},
        "Action": "sts:AssumeRole",
        # Confused-deputy guard: only THIS account's Athena may assume it.
        "Condition": {"StringEquals": {"aws:SourceAccount": account}}}]}
    arn = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "spark-calculation-returns-computed-stdout"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    policy_name = "sim2real-behav-athena-spark"
    iam.put_role_policy(RoleName=role, PolicyName=policy_name, PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow",
             "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
             "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]},
            {"Effect": "Allow",
             "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
                        "logs:DescribeLogStreams", "logs:DescribeLogGroups"],
             "Resource": f"arn:aws:logs:{ctx.region}:{account}:log-group:*"},
            {"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*",
             "Condition": {"StringEquals": {
                 "cloudwatch:namespace": "AmazonAthenaForApacheSpark"}}},
        ]}))
    # Registered immediately after the put it undoes: DeleteRole refuses while an inline policy
    # remains, and LIFO runs this BEFORE the DeleteRole registered above.
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role, PolicyName=policy_name))
    return arn


def _start_session_when_role_is_usable(ctx, workgroup):
    """StartSession, retried over the IAM propagation window of the freshly created role."""
    athena = ctx.client("athena")
    last = None
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            return athena.start_session(
                WorkGroup=workgroup,
                EngineConfiguration={"CoordinatorDpuSize": 1, "MaxConcurrentDpus": 2,
                                     "DefaultExecutorDpuSize": 1},
                SessionIdleTimeoutInMinutes=_SESSION_IDLE_TIMEOUT_MIN,
            )["SessionId"]
        except ClientError as exc:
            last = f"{exc.response.get('Error', {}).get('Code')}: " \
                   f"{exc.response.get('Error', {}).get('Message')}"
            time.sleep(5)
    raise AssertionError(
        f"StartSession never succeeded within 180s of creating the execution role; last error was "
        f"{last!r}. 'Provisioned but unusable' is a failure, not an environment limit.")


def _poll_session(athena, session_id, timeout_s=600, interval_s=5):
    """Poll GetSession to a settled state. A session that never leaves CREATING is a failure."""
    settled = ("IDLE", "BUSY", "FAILED", "TERMINATED", "DEGRADED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_session(SessionId=session_id)["Status"]["State"]
        if state in settled:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"session {session_id} never left CREATING within {timeout_s}s (last={state})")


def _poll_calculation(athena, calc_id, timeout_s=600, interval_s=3):
    """Poll GetCalculationExecution to a terminal state."""
    terminal = ("COMPLETED", "FAILED", "CANCELED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_calculation_execution(
            CalculationExecutionId=calc_id)["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"calculation {calc_id} did not reach a terminal state within {timeout_s}s (last={state})")


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A Spark calculation prints this run's marker and a sum it computed to Result.StdOutS3Uri,
    reports non-zero DpuExecutionInMillis, and returns its exact code block.
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    bucket = _make_bucket(ctx, "sim2real-behav-athena-spark-")
    role_arn = _spark_execution_role(ctx, bucket)

    wg = ctx.unique_name("sim2real-behav-athena-wg-")
    athena.create_work_group(
        Name=wg,
        Configuration={
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/spark/"},
            "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
            "ExecutionRole": role_arn,
        },
        Tags=[{"Key": "sim2real", "Value": "spark-calculation-returns-computed-stdout"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))
    engine = athena.get_work_group(WorkGroup=wg)["WorkGroup"]["Configuration"]["EngineVersion"]
    assert engine["SelectedEngineVersion"] == "PySpark engine version 3", (
        f"the workgroup must be a PySpark workgroup, got EngineVersion {engine!r}")

    session_id = _start_session_when_role_is_usable(ctx, wg)
    # An IDLE session holds live DPU capacity and bills for it.
    ctx.on_cleanup(lambda: athena.terminate_session(SessionId=session_id))
    session_state = _poll_session(athena, session_id)
    assert session_state in ("IDLE", "BUSY"), (
        f"the Spark session must become usable; it settled at {session_state!r} — "
        f"{athena.get_session(SessionId=session_id)['Status']!r}. A provisioned-but-unusable "
        f"session is a failure, not an environment limit.")

    # A per-run marker; the sum is not a literal, so Spark has to compute it.
    marker = "sim2realmark" + ctx.unique_name("").replace("-", "")[:12]
    calc_id = athena.start_calculation_execution(
        SessionId=session_id,
        Description="sim2real-behav-athena-spark-calculation",
        CodeBlock=f"print('{marker}', spark.range(1, 101).groupBy().sum().collect()[0][0])",
    )["CalculationExecutionId"]

    calc_state = _poll_calculation(athena, calc_id)
    calc = athena.get_calculation_execution(CalculationExecutionId=calc_id)
    assert calc_state == "COMPLETED", (
        f"the calculation must complete; it reached {calc_state!r} — {calc.get('Status')!r}")
    assert calc["SessionId"] == session_id, (
        f"the calculation must be attributed to the session that ran it, got "
        f"{calc.get('SessionId')!r} not {session_id!r}")

    stdout_uri = calc["Result"]["StdOutS3Uri"]
    out_bucket, out_key = _split_s3_uri(stdout_uri)
    assert out_bucket == bucket, (
        f"the calculation's stdout must land in the workgroup's own output bucket {bucket!r}, got "
        f"{stdout_uri!r}")
    stdout_text = s3.get_object(Bucket=out_bucket, Key=out_key)["Body"].read().decode()
    assert marker in stdout_text, (
        f"the submitted PySpark did not run: this run's marker {marker!r} is absent from the "
        f"stdout object at {stdout_uri!r}, which holds {stdout_text[:300]!r}")
    assert stdout_text.strip() == f"{marker} {_EXPECTED_SUM}", (
        f"Spark must print the marker followed by the sum it computed for itself "
        f"({_EXPECTED_SUM} = sum 1..100); stdout was {stdout_text[:300]!r}")

    dpu_ms = calc["Statistics"]["DpuExecutionInMillis"]
    assert dpu_ms > 0, (
        f"a calculation that really ran on Spark consumes DPU time, got "
        f"DpuExecutionInMillis={dpu_ms!r} — a stub reports zero")

    code_back = athena.get_calculation_execution_code(
        CalculationExecutionId=calc_id)["CodeBlock"]
    assert code_back == (
        f"print('{marker}', spark.range(1, 101).groupBy().sum().collect()[0][0])"), (
        f"GetCalculationExecutionCode must return the exact code block submitted, got "
        f"{code_back!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
