"""dicom-import-job-invalid-role-reaches-failed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dicom-import-job-invalid-role-reaches-failed"
GROUP = "state"
SERVICES = ["medical-imaging"]


def _create_datastore_retry(mi, ctx, timeout_s: float = 180.0) -> str:
    name = ctx.unique_name("sim2real-mi-ds-")
    token = ctx.unique_name("sim2real-mi-tok-")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return mi.create_datastore(datastoreName=name, clientToken=token)["datastoreId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ThrottlingException", "TooManyRequestsException") and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _delete_datastore_retry(mi, datastore_id: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            mi.delete_datastore(datastoreId=datastore_id)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ConflictException" and time.monotonic() < deadline:
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


def _create_import_role_and_bucket(ctx, account_id: str) -> dict:
    """A bucket that exists, with a placeholder object under the input prefix, plus a role
    AWS HealthImaging can assume and that holds the S3 permissions the job needs -- the
    positive control that proves the account and datastore are otherwise healthy, so the
    negative below is known to be testing the missing role and nothing else."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-mi-ctrl-").lower().replace("_", "-")
    # us-east-1 is a literal here because S3 rejects an explicit LocationConstraint for it,
    # not a hardcoded target region -- ctx.region still drives which region this bucket exists in.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _empty_and_delete_bucket() -> None:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete_bucket)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="in/placeholder.dcm", Body=b"not a real DICOM P10 file")

    role_name = ctx.unique_name("sim2real-behav-mi-goodrole-")
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
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

    return {"bucket": bucket, "role_arn": f"arn:aws:iam::{account_id}:role/{role_name}"}


def _start_import_job_retry(mi, timeout_s: float = 90.0, **kwargs) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return mi.start_dicom_import_job(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "AccessDeniedException" and time.monotonic() < deadline:
                # role/policy propagation lag, not the rejection under test
                time.sleep(5)
                continue
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartDICOMImportJob with a data-access role that does not exist fails AccessDeniedException with the
    exact message and no job appears in ListDICOMImportJobs, while the same datastore accepts a job with
    an assumable role, which ListDICOMImportJobs lists."""
    mi = ctx.client("medical-imaging")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    datastore_id = _create_datastore_retry(mi, ctx)
    ctx.on_cleanup(lambda: _delete_datastore_retry(mi, datastore_id))
    _wait_active(mi, datastore_id)

    # Positive control: a role that exists and can be assumed is accepted synchronously.
    good_infra = _create_import_role_and_bucket(ctx, account_id)
    good_job_id = _start_import_job_retry(
        mi,
        jobName=ctx.unique_name("sim2real-mi-job-good-"),
        datastoreId=datastore_id,
        dataAccessRoleArn=good_infra["role_arn"],
        clientToken=ctx.unique_name("sim2real-mi-tok-"),
        inputS3Uri=f"s3://{good_infra['bucket']}/in/",
        outputS3Uri=f"s3://{good_infra['bucket']}/out/",
    )["jobId"]

    jobs_after_positive = mi.list_dicom_import_jobs(datastoreId=datastore_id)["jobSummaries"]
    assert any(j["jobId"] == good_job_id for j in jobs_after_positive), (
        f"positive-control job {good_job_id} missing from ListDICOMImportJobs: {jobs_after_positive}"
    )

    # Negative: the role does not exist at all, so HealthImaging can never assume it.
    bogus_bucket = ctx.unique_name("sim2real-mi-nobucket-").lower()
    nonexistent_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-behav-mi-norole-')}"
    bad_job_name = ctx.unique_name("sim2real-mi-job-bad-")

    try:
        mi.start_dicom_import_job(
            jobName=bad_job_name,
            datastoreId=datastore_id,
            dataAccessRoleArn=nonexistent_role_arn,
            clientToken=ctx.unique_name("sim2real-mi-tok-"),
            inputS3Uri=f"s3://{bogus_bucket}/in/",
            outputS3Uri=f"s3://{bogus_bucket}/out/",
        )
        raise AssertionError("StartDICOMImportJob unexpectedly succeeded with a nonexistent role")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
        message = err.response["Error"].get("Message")
        expected_message = (
            f"Amazon Medical Imaging is not authorized to assume role: {nonexistent_role_arn}. "
            "Please update the role's trust policy."
        )
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected call created no job, at an independent read -- the only
    # job on this datastore is still the positive control from above, not a new one.
    jobs_after_negative = mi.list_dicom_import_jobs(datastoreId=datastore_id)["jobSummaries"]
    assert not any(j["jobName"] == bad_job_name for j in jobs_after_negative), (
        f"rejected job {bad_job_name} unexpectedly appeared in ListDICOMImportJobs: {jobs_after_negative}"
    )
    assert len(jobs_after_negative) == len(jobs_after_positive), (
        f"job count changed after the rejected call: before={jobs_after_positive} "
        f"after={jobs_after_negative}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
