"""iam-role-trust-glue-amazonaws-com-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "iam-role-trust-glue-amazonaws-com-positive"
GROUP = "iam-trust"
SERVICES = ["glue", "sqs"]

_SCRIPT = (
    "import sys\n"
    "print('GLUE_JOB_RAN_OK')\n"
    "sys.exit(0)\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role trusting glue.amazonaws.com is actually assumed by the Glue service to run a job."""
    script_uri, bucket = _upload_script(ctx, _SCRIPT)
    bucket_arn = f"arn:aws:s3:::{bucket}/*"
    role_name, role_arn = _create_glue_role(ctx, bucket_arn)
    job_name = _create_pythonshell_job(ctx, role_arn, script_uri)

    final = _run_job_until_role_trust_settles(ctx, job_name, timeout_s=180, interval_s=15)
    # If glue.amazonaws.com could not assume the role, StartJobRun/the run itself fails
    # long before doing any work; SUCCEEDED here is direct proof the trust relationship
    # was honored by the Glue service.
    assert final["JobRunState"] == "SUCCEEDED", f"unexpected terminal state: {final}"


def _upload_script(ctx, body: str) -> tuple[str, str]:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-scripts-")
    # CreateBucket rejects an explicit LocationConstraint matching the default
    # region (us-east-1); this is that API quirk, not a hardcoded target region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_object(Bucket=bucket, Key="script.py", Body=body.encode("utf-8"))
    return f"s3://{bucket}/script.py", bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    s3.delete_bucket(Bucket=bucket)


def _create_glue_role(ctx, script_bucket_arn: str, extra_statements: list[dict[str, Any]] | None = None):
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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    statements = [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": script_bucket_arn},
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        },
    ]
    if extra_statements:
        statements.extend(extra_statements)
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=role_name, PolicyName="inline-perms", PolicyDocument=json.dumps(policy_doc))
    # LIFO cleanup: delete_role must run only after the inline policy is gone.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-perms"))
    return role_name, role_arn


def _create_pythonshell_job(ctx, role_arn: str, script_uri: str) -> str:
    glue = ctx.client("glue")
    job_name = ctx.unique_name("sim2real-glue-job-")
    glue.create_job(
        Name=job_name,
        Role=role_arn,
        Command={"Name": "pythonshell", "ScriptLocation": script_uri, "PythonVersion": "3.9"},
        MaxCapacity=0.0625,
        Timeout=5,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))
    return job_name


def _start_job_run_with_retry(ctx, job_name: str, arguments: dict[str, str], timeout_s: float = 90, interval_s: float = 10) -> str:
    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = glue.start_job_run(JobName=job_name, Arguments=arguments)
            return resp["JobRunId"]
        except Exception as exc:  # IAM role propagation delay right after CreateRole
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"start_job_run kept failing: {last_err}")


def _wait_for_job_run(ctx, job_name: str, run_id: str, timeout_s: float = 480, interval_s: float = 15) -> dict[str, Any]:
    glue = ctx.client("glue")
    terminal = {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"}
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        resp = glue.get_job_run(JobName=job_name, RunId=run_id)
        last = resp["JobRun"]
        if last["JobRunState"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"job run did not reach terminal state in {timeout_s}s, last={last}")


# A freshly created role's trust document is eventually consistent: StartJobRun can be
# accepted before Glue's own assume-role check can see it, and the run then fails within
# seconds with this specific, transient message. Retry the run itself (not just the API
# call) only for that exact signature, bounded by a deadline — never an unconditional sleep.
_ROLE_TRUST_NOT_PROPAGATED = "should be given assume role permissions for Glue Service"


def _run_job_until_role_trust_settles(ctx, job_name: str, timeout_s: float = 180, interval_s: float = 15) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while True:
        run_id = _start_job_run_with_retry(ctx, job_name, arguments={})
        last = _wait_for_job_run(ctx, job_name, run_id, timeout_s=480, interval_s=15)
        if last["JobRunState"] != "FAILED" or _ROLE_TRUST_NOT_PROPAGATED not in (last.get("ErrorMessage") or ""):
            return last
        if time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
