"""glue-python-shell-job-writes-its-computed-output-to-s3."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "glue-python-shell-job-writes-its-computed-output-to-s3"
GROUP = 'jobs'
SERVICES = ['glue', 's3']

# Uploaded to S3 and executed by Glue-managed compute. It reads its own job arguments,
# computes seed*3+1 and PUTs the result, so the only evidence it ran is the object.
_SCRIPT = b"""import sys
import boto3

args = {}
for i, a in enumerate(sys.argv):
    if a.startswith('--') and i + 1 < len(sys.argv):
        args[a[2:]] = sys.argv[i + 1]
seed = int(args['SEED'])
bucket, key = args['OUT'][len('s3://'):].split('/', 1)
boto3.client('s3').put_object(Bucket=bucket, Key=key, Body=str(seed * 3 + 1).encode())
"""


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """A pythonshell job runs a script this check uploaded, receives its job argument and writes
    the value it computed from that argument to S3."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    seed = 7 + int(time.time()) % 90
    out_key = "out/computed.txt"

    bucket = ctx.unique_name("sim2real-behav-gluejob-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real",
                                                             "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="scripts/job.py", Body=_SCRIPT)

    role_arn = _create_glue_role(ctx, iam, bucket, write=True)

    job = ctx.unique_name("sim2real-behav-gluejob-")
    glue.create_job(
        Name=job, Role=role_arn,
        Command={"Name": "pythonshell", "PythonVersion": "3.9",
                 "ScriptLocation": f"s3://{bucket}/scripts/job.py"},
        MaxCapacity=0.0625, GlueVersion="3.0",
        # A retried run races Glue's concurrency accounting, which lags the previous run's
        # own terminal state; MaxConcurrentRuns=1 would make the retry below fail outright.
        ExecutionProperty={"MaxConcurrentRuns": 5},
        Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_job(JobName=job),
                                         f"glue job {job}"))

    job_run = _run_job_to_terminal(
        glue, job, {"--SEED": str(seed), "--OUT": f"s3://{bucket}/{out_key}"})

    assert job_run["JobRunState"] == "SUCCEEDED", (
        f"job run ended {job_run['JobRunState']!r}: {job_run.get('ErrorMessage')!r}"
    )

    body = _get_object(s3, bucket, out_key)
    assert body is not None, (
        f"no object at {out_key!r} after a SUCCEEDED run; the prefix holds "
        f"{_list_keys(s3, bucket, 'out/')!r}"
    )
    expected = str(seed * 3 + 1).encode()
    assert body.strip() == expected, (
        f"the job wrote {body[:80]!r}, expected {expected!r} for --SEED {seed!r}"
    )
    assert job_run["Arguments"]["--SEED"] == str(seed), (
        f"run arguments were {job_run['Arguments']!r}, expected --SEED {str(seed)!r}"
    )
    assert job_run["ExecutionTime"] > 0, (
        f"ExecutionTime was {job_run['ExecutionTime']!r} for a SUCCEEDED run, so no "
        f"compute was billed and nothing actually ran"
    )
    assert _list_keys(s3, bucket, "out/") == [out_key], (
        f"the run wrote {_list_keys(s3, bucket, 'out/')!r} under out/, expected exactly "
        f"{[out_key]!r}"
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
