"""glue-job-role-without-write-permission-fails-the-run-and-writes-no-output."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "glue-job-role-without-write-permission-fails-the-run-and-writes-no-output"
GROUP = 'overly-permissive'
SERVICES = ['glue', 's3']

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


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """The same job under a role that cannot write fails the run, names AccessDenied on PutObject
    in its ErrorMessage and writes no object; the identical job whose role grants s3:PutObject
    writes it."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    seed = 4 + int(time.time()) % 90
    denied_key = "out/denied.txt"
    allowed_key = "out/allowed.txt"

    bucket = ctx.unique_name("sim2real-behav-gluerodenied-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real",
                                                             "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="scripts/job.py", Body=_SCRIPT)

    # The one broken thing: read-only on the very bucket the script must write to.
    read_only_arn = _create_glue_role(ctx, iam, bucket, ["s3:GetObject"])
    read_write_arn = _create_glue_role(ctx, iam, bucket, ["s3:GetObject", "s3:PutObject"])

    denied_job = _create_job(ctx, glue, bucket, read_only_arn, "gluejobro-")
    allowed_job = _create_job(ctx, glue, bucket, read_write_arn, "gluejobrw-")

    denied_run = _run_job_to_terminal(
        glue, denied_job, {"--SEED": str(seed), "--OUT": f"s3://{bucket}/{denied_key}"})

    assert denied_run["JobRunState"] == "FAILED", (
        f"the read-only run ended {denied_run['JobRunState']!r}, so the missing "
        f"s3:PutObject did not stop it: {denied_run.get('ErrorMessage')!r}"
    )
    message = denied_run.get("ErrorMessage") or ""
    assert "AccessDenied" in message and "PutObject" in message, (
        f"the run failed for the wrong reason; ErrorMessage was {message!r}, expected it to "
        f"name AccessDenied on PutObject"
    )
    keys_after_denied = _list_keys(s3, bucket, "out/")
    assert denied_key not in keys_after_denied, (
        f"the read-only run wrote {denied_key!r} anyway; out/ holds "
        f"{keys_after_denied!r}"
    )
    assert keys_after_denied == [], (
        f"the read-only run left {keys_after_denied!r} under out/, expected nothing"
    )

    allowed_run = _run_job_to_terminal(
        glue, allowed_job, {"--SEED": str(seed), "--OUT": f"s3://{bucket}/{allowed_key}"})

    assert allowed_run["JobRunState"] == "SUCCEEDED", (
        f"the positive control ended {allowed_run['JobRunState']!r}: "
        f"{allowed_run.get('ErrorMessage')!r}"
    )
    body = _get_object(s3, bucket, allowed_key)
    expected = str(seed * 3 + 1).encode()
    assert body is not None and body.strip() == expected, (
        f"the write-capable run wrote {body!r}, expected {expected!r}"
    )
    denied_command = glue.get_job(JobName=denied_job)["Job"]["Command"]
    allowed_command = glue.get_job(JobName=allowed_job)["Job"]["Command"]
    assert denied_command == allowed_command, (
        f"the two jobs differ beyond the role, so the comparison is not controlled: "
        f"{denied_command!r} vs {allowed_command!r}"
    )
    assert _list_keys(s3, bucket, "out/") == [allowed_key], (
        f"out/ finally holds {_list_keys(s3, bucket, 'out/')!r}, expected only "
        f"{[allowed_key]!r}"
    )


# ===== helpers =====

def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _create_glue_role(ctx, iam, bucket: str, actions: list) -> str:
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


def _create_job(ctx, glue, bucket: str, role_arn: str, prefix: str) -> str:
    job = ctx.unique_name("sim2real-behav-" + prefix)
    glue.create_job(
        Name=job, Role=role_arn,
        Command={"Name": "pythonshell", "PythonVersion": "3.9",
                 "ScriptLocation": f"s3://{bucket}/scripts/job.py"},
        MaxCapacity=0.0625, GlueVersion="3.0",
        ExecutionProperty={"MaxConcurrentRuns": 5},
        Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_job(JobName=job),
                                         f"glue job {job}"))
    return job


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
