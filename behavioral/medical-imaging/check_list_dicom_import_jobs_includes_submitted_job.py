"""list-dicom-import-jobs-includes-submitted-job."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-dicom-import-jobs-includes-submitted-job"
GROUP = "control-plane"
SERVICES = ["medical-imaging"]


def _create_datastore_retry(mi, ctx, timeout_s: float = 600.0) -> str:
    name = ctx.unique_name("sim2real-mi-ds-")
    token = ctx.unique_name("sim2real-mi-tok-")
    deadline = time.monotonic() + timeout_s
    delay = 5.0
    while True:
        try:
            return mi.create_datastore(
                datastoreName=name, clientToken=token, tags={"sim2real": CHECK}
            )["datastoreId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ThrottlingException", "TooManyRequestsException") and time.monotonic() < deadline:
                time.sleep(delay + random.random() * delay)
                delay = min(delay * 1.7, 60.0)
                continue
            raise


def _delete_datastore_retry(mi, datastore_id: str, timeout_s: float = 600.0):
    deadline = time.monotonic() + timeout_s
    delay = 5.0
    while True:
        try:
            return mi.delete_datastore(datastoreId=datastore_id)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ThrottlingException", "TooManyRequestsException") and time.monotonic() < deadline:
                time.sleep(delay + random.random() * delay)
                delay = min(delay * 1.7, 60.0)
                continue
            raise


def _create_import_role_and_bucket(ctx) -> dict:
    """A bucket that exists, with a placeholder (non-DICOM) object under the input prefix
    (StartDICOMImportJob synchronously validates that at least one object matches the input
    S3 URI), plus a role AWS HealthImaging can assume (correct trust policy) *and* that has
    the minimal S3 read/write permissions the service also validates synchronously. This
    passes synchronous validation, submits, and then fails asynchronously once the service
    tries to parse the placeholder object as a DICOM P10 file."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-mi-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _empty_and_delete_bucket():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete_bucket)
    s3.put_object(Bucket=bucket, Key="in/placeholder.dcm", Body=b"not a real DICOM P10 file")

    role_name = ctx.unique_name("sim2real-behav-mi-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "medical-imaging.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": [f"arn:aws:s3:::{bucket}"]},
                {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": [f"arn:aws:s3:::{bucket}/in/*"]},
                {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": [f"arn:aws:s3:::{bucket}/out/*"]},
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName="s3access", PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3access"))
    return {"bucket": bucket, "role_arn": role_arn}



def _start_import_job_retry(mi, timeout_s: float = 120.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return mi.start_dicom_import_job(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException") and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise



def _wait_active(mi, datastore_id: str, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]["datastoreStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError("datastore never reached ACTIVE")


def _wait_terminal(mi, datastore_id: str, job_id: str, timeout_s: float = 240.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = mi.get_dicom_import_job(datastoreId=datastore_id, jobId=job_id)["jobProperties"]["jobStatus"]
        if status in ("COMPLETED", "FAILED"):
            return
        time.sleep(3)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly started DICOM import job shows up in ListDICOMImportJobs for its datastore,
    with the summary's jobStatus matching GetDICOMImportJob."""
    mi = ctx.client("medical-imaging")

    datastore_id = _create_datastore_retry(mi, ctx)
    ctx.on_cleanup(lambda: _delete_datastore_retry(mi, datastore_id))
    _wait_active(mi, datastore_id)

    role_setup = _create_import_role_and_bucket(ctx)
    role_arn = role_setup["role_arn"]
    bucket = role_setup["bucket"]
    job_name = ctx.unique_name("sim2real-mi-job-")
    job_id = _start_import_job_retry(
        mi,
        jobName=job_name,
        datastoreId=datastore_id,
        dataAccessRoleArn=role_arn,
        clientToken=ctx.unique_name("sim2real-mi-tok-"),
        inputS3Uri=f"s3://{bucket}/in/",
        outputS3Uri=f"s3://{bucket}/out/",
    )["jobId"]

    jobs = mi.list_dicom_import_jobs(datastoreId=datastore_id)["jobSummaries"]
    matching = [j for j in jobs if j["jobId"] == job_id]
    assert len(matching) == 1, f"expected exactly one summary for {job_id}, got {matching}"
    assert matching[0]["jobName"] == job_name, f"expected jobName {job_name!r}, got {matching[0]['jobName']!r}"
    assert matching[0]["datastoreId"] == datastore_id, (
        f"expected datastoreId {datastore_id!r}, got {matching[0]['datastoreId']!r}"
    )

    get_status = mi.get_dicom_import_job(datastoreId=datastore_id, jobId=job_id)["jobProperties"]["jobStatus"]
    assert matching[0]["jobStatus"] == get_status, (
        f"list summary jobStatus {matching[0]['jobStatus']!r} does not match "
        f"GetDICOMImportJob jobStatus {get_status!r}"
    )

    _wait_terminal(mi, datastore_id, job_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
