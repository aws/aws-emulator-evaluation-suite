"""start-dicom-import-job-on-creating-datastore-conflict-rejected."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-dicom-import-job-on-creating-datastore-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["medical-imaging"]


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected StartDICOMImportJob to be rejected, but it SUCCEEDED and returned {result!r}")


def _is_throttle(code: str) -> bool:
    # HealthImaging's edge throttle can return a compound code like
    # "ThrottlingException, TooManyRequestsException" rather than either alone.
    return "ThrottlingException" in code or "TooManyRequestsException" in code


def _create_datastore_retry(mi, ctx, timeout_s: float = 1500.0) -> str:
    name = ctx.unique_name("sim2real-mi-ds-")
    token = ctx.unique_name("sim2real-mi-tok-")
    deadline = time.monotonic() + timeout_s
    delay = 10.0
    while True:
        try:
            return mi.create_datastore(
                datastoreName=name, clientToken=token, tags={"sim2real": "true"}
            )["datastoreId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if _is_throttle(code) and time.monotonic() < deadline:
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
            if _is_throttle(code) and time.monotonic() < deadline:
                time.sleep(delay + random.random() * delay)
                delay = min(delay * 1.6, 120.0)
                continue
            raise


def _datastore_status_retry(mi, datastore_id: str, timeout_s: float = 30.0) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"][
                "datastoreStatus"
            ]
        except ClientError as err:
            if _is_throttle(err.response["Error"]["Code"]) and time.monotonic() < deadline:
                time.sleep(1.0 + random.random())
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
    # us-east-1 is the one region where S3 CreateBucket rejects an explicit LocationConstraint.
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
    """Retries only on AccessDeniedException/ValidationException (IAM propagation delay) --
    any other error (e.g. ConflictException) must propagate immediately, unmasked."""
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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartDICOMImportJob is rejected with ConflictException when the target datastore is
    still CREATING and has never accepted a job; the very same call succeeds once the
    datastore reaches ACTIVE (positive control)."""
    mi = ctx.client("medical-imaging")

    # Create the role and bucket first so any IAM-propagation delay overlaps with datastore
    # creation rather than eating into the CREATING window we need to race against below.
    role_setup = _create_import_role_and_bucket(ctx)
    role_arn = role_setup["role_arn"]
    bucket = role_setup["bucket"]

    datastore_id = _create_datastore_retry(mi, ctx)
    ctx.on_cleanup(lambda: _delete_datastore_retry(mi, datastore_id))

    # Precondition: the datastore is still CREATING, so the rejection below is about its status.
    status = _datastore_status_retry(mi, datastore_id)
    assert status == "CREATING", (
        f"expected the just-created datastore to be CREATING before the import attempt, got {status!r}"
    )

    # Break exactly one thing: start a job before the datastore has finished CREATING.
    code, message = _client_error(
        lambda: mi.start_dicom_import_job(
            jobName=ctx.unique_name("sim2real-mi-job-"),
            datastoreId=datastore_id,
            dataAccessRoleArn=role_arn,
            clientToken=ctx.unique_name("sim2real-mi-tok-"),
            inputS3Uri=f"s3://{bucket}/in/",
            outputS3Uri=f"s3://{bucket}/out/",
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = "The datastore is not active."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    deadline = time.monotonic() + 300
    active = False
    while time.monotonic() < deadline:
        if mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]["datastoreStatus"] == "ACTIVE":
            active = True
            break
        time.sleep(3)
    assert active, "datastore never reached ACTIVE"

    # Effect absent: no job was ever created on this datastore (ListDICOMImportJobs itself
    # requires an ACTIVE datastore, so this can only be checked now).
    jobs = mi.list_dicom_import_jobs(datastoreId=datastore_id)["jobSummaries"]
    assert jobs == []


    # Positive control: the identical call succeeds now that the datastore is ACTIVE.
    start_resp = _start_import_job_retry(
        mi,
        jobName=ctx.unique_name("sim2real-mi-job-"),
        datastoreId=datastore_id,
        dataAccessRoleArn=role_arn,
        clientToken=ctx.unique_name("sim2real-mi-tok-"),
        inputS3Uri=f"s3://{bucket}/in/",
        outputS3Uri=f"s3://{bucket}/out/",
    )
    assert start_resp["jobStatus"] == "SUBMITTED"

    # Independent read at the destination: confirm via GetDICOMImportJob (not the
    # StartDICOMImportJob response) that the job really was accepted, then let it resolve
    # (it will fail, since the placeholder object is not a real DICOM P10 file) before cleanup.
    job_id = start_resp["jobId"]
    props = mi.get_dicom_import_job(datastoreId=datastore_id, jobId=job_id)["jobProperties"]
    assert props["jobStatus"] in ("SUBMITTED", "IN_PROGRESS", "COMPLETED", "FAILED")

    deadline = time.monotonic() + 240
    terminal_status = props["jobStatus"]
    while time.monotonic() < deadline:
        terminal_status = mi.get_dicom_import_job(datastoreId=datastore_id, jobId=job_id)["jobProperties"]["jobStatus"]
        if terminal_status in ("COMPLETED", "FAILED"):
            break
        time.sleep(3)
    assert terminal_status in ("COMPLETED", "FAILED"), terminal_status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
