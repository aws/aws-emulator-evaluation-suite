"""delete-datastore-conflicts-with-active-import-job."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-datastore-conflicts-with-active-import-job"
GROUP = "overly-permissive"
SERVICES = ["medical-imaging"]


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected DeleteDatastore to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_datastore_retry(mi, ctx, timeout_s: float = 1500.0) -> str:
    import random

    name = ctx.unique_name("sim2real-mi-ds-")
    token = ctx.unique_name("sim2real-mi-tok-")
    deadline = time.monotonic() + timeout_s
    delay = 10.0
    while True:
        try:
            return mi.create_datastore(datastoreName=name, clientToken=token)["datastoreId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            # HealthImaging's edge throttle can return a compound code like
            # "ThrottlingException, TooManyRequestsException" rather than either alone.
            is_throttle = "ThrottlingException" in code or "TooManyRequestsException" in code
            if is_throttle and time.monotonic() < deadline:
                time.sleep(delay + random.random() * delay)
                delay = min(delay * 1.6, 120.0)
                continue
            raise


def _delete_datastore_retry(mi, datastore_id: str, timeout_s: float = 2400.0):
    import random

    deadline = time.monotonic() + timeout_s
    delay = 15.0
    while True:
        try:
            return mi.delete_datastore(datastoreId=datastore_id)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            # HealthImaging's edge throttle can return a compound code like
            # "ThrottlingException, TooManyRequestsException" rather than either alone.
            is_throttle = "ThrottlingException" in code or "TooManyRequestsException" in code
            if is_throttle and time.monotonic() < deadline:
                time.sleep(delay + random.random() * delay)
                delay = min(delay * 1.6, 150.0)
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
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


def _wait_terminal(mi, datastore_id: str, job_id: str, timeout_s: float = 240.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = mi.get_dicom_import_job(datastoreId=datastore_id, jobId=job_id)["jobProperties"]["jobStatus"]
        if status in ("COMPLETED", "FAILED"):
            return status
        time.sleep(3)
    return status


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDatastore is rejected with ConflictException while a DICOM import job on that
    datastore is still in flight; the datastore is left untouched. Once the job resolves to a
    terminal state, the very same DeleteDatastore call succeeds (positive control)."""
    mi = ctx.client("medical-imaging")

    datastore_id = _create_datastore_retry(mi, ctx)

    def _cleanup_delete():
        try:
            _delete_datastore_retry(mi, datastore_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_delete)
    _wait_active(mi, datastore_id)

    role_setup = _create_import_role_and_bucket(ctx)
    role_arn = role_setup["role_arn"]
    bucket = role_setup["bucket"]
    job_id = _start_import_job_retry(
        mi,
        jobName=ctx.unique_name("sim2real-mi-job-"),
        datastoreId=datastore_id,
        dataAccessRoleArn=role_arn,
        clientToken=ctx.unique_name("sim2real-mi-tok-"),
        inputS3Uri=f"s3://{bucket}/in/",
        outputS3Uri=f"s3://{bucket}/out/",
    )["jobId"]

    # Break exactly one thing: try to delete the datastore while the job is still active.
    code, message = _client_error(lambda: mi.delete_datastore(datastoreId=datastore_id))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = "Cannot delete a datastore with running import jobs"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the datastore was not deleted.
    still_there = mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]
    assert still_there["datastoreStatus"] == "ACTIVE", (
        f"expected ACTIVE after the rejected delete, got {still_there['datastoreStatus']!r}"
    )

    final_status = _wait_terminal(mi, datastore_id, job_id)
    assert final_status in ("COMPLETED", "FAILED"), f"expected a terminal job status, got {final_status!r}"

    # Positive control: once the job is resolved, the identical delete call succeeds.
    del_resp = _delete_datastore_retry(mi, datastore_id)
    assert del_resp["datastoreStatus"] == "DELETING", (
        f"expected DeleteDatastore's own response to report DELETING, got {del_resp['datastoreStatus']!r}"
    )

    final_ds_status = None
    purged = False
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            final_ds_status = mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]["datastoreStatus"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                purged = True
                break
            raise
        if final_ds_status == "DELETED":
            break
        time.sleep(3)
    assert purged or final_ds_status == "DELETED", (
        f"datastore did not reach a terminal deleted state via an independent read, last status={final_ds_status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
