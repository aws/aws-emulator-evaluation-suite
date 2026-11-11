"""get-dicom-import-job-reflects-submitted-properties."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-dicom-import-job-reflects-submitted-properties"
GROUP = "error-semantics"
SERVICES = ["medical-imaging"]


_MGMT_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-mi"}


def _create_datastore_retry(mi, ctx, timeout_s: float = 1500.0) -> str:
    name = ctx.unique_name("sim2real-mi-ds-")
    token = ctx.unique_name("sim2real-mi-tok-")
    deadline = time.monotonic() + timeout_s
    delay = 10.0
    while True:
        try:
            return mi.create_datastore(datastoreName=name, clientToken=token, tags=_MGMT_TAGS)["datastoreId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ThrottlingException", "TooManyRequestsException") and time.monotonic() < deadline:
                time.sleep(delay + random.random() * delay)
                delay = min(delay * 1.6, 120.0)
                continue
            raise


def _delete_datastore_retry(mi, datastore_id: str, timeout_s: float = 1500.0):
    deadline = time.monotonic() + timeout_s
    delay = 10.0
    while True:
        try:
            return mi.delete_datastore(datastoreId=datastore_id)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ThrottlingException", "TooManyRequestsException") and time.monotonic() < deadline:
                time.sleep(delay + random.random() * delay)
                delay = min(delay * 1.6, 120.0)
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _MGMT_TAGS.items()]})
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
        Tags=[{"Key": k, "Value": v} for k, v in _MGMT_TAGS.items()],
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
    """Retries on AccessDeniedException/ValidationException while IAM eventual consistency
    makes the just-created role or its just-attached policy temporarily unrecognized."""
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
    """GetDICOMImportJob echoes back the exact datastoreId, dataAccessRoleArn, inputS3Uri and
    outputS3Uri that were supplied to StartDICOMImportJob, while the job is still in flight."""
    mi = ctx.client("medical-imaging")

    datastore_id = _create_datastore_retry(mi, ctx)
    ctx.on_cleanup(lambda: _delete_datastore_retry(mi, datastore_id))
    _wait_active(mi, datastore_id)

    role_setup = _create_import_role_and_bucket(ctx)
    role_arn = role_setup["role_arn"]
    bucket = role_setup["bucket"]
    input_uri = f"s3://{bucket}/in/"
    output_uri = f"s3://{bucket}/out/"
    job_name = ctx.unique_name("sim2real-mi-job-")

    start_resp = _start_import_job_retry(
        mi,
        jobName=job_name,
        datastoreId=datastore_id,
        dataAccessRoleArn=role_arn,
        clientToken=ctx.unique_name("sim2real-mi-tok-"),
        inputS3Uri=input_uri,
        outputS3Uri=output_uri,
    )
    job_id = start_resp["jobId"]

    props = mi.get_dicom_import_job(datastoreId=datastore_id, jobId=job_id)["jobProperties"]
    assert props["jobId"] == job_id, f"expected jobId {job_id!r}, got {props['jobId']!r}"
    assert props["jobName"] == job_name, f"expected jobName {job_name!r}, got {props['jobName']!r}"
    assert props["datastoreId"] == datastore_id, (
        f"expected datastoreId {datastore_id!r}, got {props['datastoreId']!r}"
    )
    assert props["dataAccessRoleArn"] == role_arn, (
        f"expected dataAccessRoleArn {role_arn!r}, got {props['dataAccessRoleArn']!r}"
    )
    assert props["inputS3Uri"] == input_uri, f"expected inputS3Uri {input_uri!r}, got {props['inputS3Uri']!r}"
    # AWS HealthImaging may append a job-specific subfolder under the requested output prefix
    # (e.g. "<prefix>/<datastoreId>-DicomImport-<jobId>/"); require the prefix, not equality.
    assert props["outputS3Uri"].startswith(output_uri), (
        f"expected outputS3Uri to start with {output_uri!r}, got {props['outputS3Uri']!r}"
    )
    # Read immediately after StartDICOMImportJob returns, before any wait: the job cannot yet
    # be terminal, so COMPLETED/FAILED here would mean the properties were not read in flight.
    assert props["jobStatus"] in ("SUBMITTED", "IN_PROGRESS"), (
        f"expected job still in flight right after start, got jobStatus={props['jobStatus']!r}"
    )

    _wait_terminal(mi, datastore_id, job_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
