"""start-import-job-into-creating-datastore-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-import-job-into-creating-datastore-rejected"
GROUP = "overly-permissive"
SERVICES = ["healthlake"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartFHIRImportJob on a CREATING datastore fails with AccessDeniedException and the
    exact "not active" message and starts no job; once the datastore is ACTIVE the same call
    starts a job that is listed and reaches COMPLETED."""
    healthlake = ctx.client("healthlake")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    sts.get_caller_identity()["Account"]

    managed_tag = {"Key": "sim2real:managed", "Value": "true"}

    bucket = ctx.unique_name("sim2real-hl-notactive").lower().replace("_", "-")
    # us-east-1 rejects an explicit LocationConstraint on create_bucket; every other region requires one.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [managed_tag]})
    ctx.on_cleanup(lambda: _best_effort(lambda: _empty_and_delete_bucket(s3, bucket)))

    key_arn = kms.create_key(
        Description="sim2real HealthLake not-active test key",
        Tags=[{"TagKey": managed_tag["Key"], "TagValue": managed_tag["Value"]}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))
    )

    role_name = ctx.unique_name("sim2real-hl-notactive-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "healthlake.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=[managed_tag]
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))

    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{bucket}"},
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["kms:DescribeKey", "kms:GenerateDataKey*"], "Resource": key_arn},
        ],
    }
    policy_name = "sim2real-hl-notactive-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions_policy))
    ctx.on_cleanup(
        lambda: _best_effort(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )

    # a bulk FHIR import assigns no server-side id, so the record needs a valid one supplied
    # up front -- a bare `{"resourceType":"Patient"}` fails at import time as a "customer error".
    patient_id = ctx.unique_name("sim2real-hl-notactive-patient-")
    s3.put_object(
        Bucket=bucket,
        Key="input/patient.ndjson",
        Body=(json.dumps({"resourceType": "Patient", "id": patient_id}) + "\n").encode(),
    )

    def _start_import():
        return healthlake.start_fhir_import_job(
            JobName=ctx.unique_name("sim2real-import-job-"),
            InputDataConfig={"S3Uri": f"s3://{bucket}/input/"},
            JobOutputDataConfig={"S3Configuration": {"S3Uri": f"s3://{bucket}/output/", "KmsKeyId": key_arn}},
            DataAccessRoleArn=role_arn,
            DatastoreId=datastore_id,
            ClientToken=ctx.unique_name("sim2real-token-"),
        )

    # The datastore is created last, right before the import attempt, so no other setup step
    # runs inside its CREATING window.
    ds_name = ctx.unique_name("sim2real-hl-notactive-")
    created_ds = healthlake.create_fhir_datastore(
        DatastoreName=ds_name, DatastoreTypeVersion="R4", Tags=[managed_tag]
    )
    datastore_id = created_ds["DatastoreId"]
    assert created_ds["DatastoreStatus"] == "CREATING", (
        f"expected a freshly created datastore to be CREATING, got {created_ds['DatastoreStatus']!r}"
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: healthlake.delete_fhir_datastore(DatastoreId=datastore_id)))

    # Rejected while CREATING -- with AccessDeniedException, not ValidationException: this is
    # HealthLake's deterministic answer for "datastore is not active", not an IAM-propagation
    # race, so this call is not wrapped in the AccessDenied retry the positive control below uses.
    # precondition: the datastore created just above is still CREATING when the import is sent.
    before = healthlake.describe_fhir_datastore(DatastoreId=datastore_id)["DatastoreProperties"]
    assert before["DatastoreStatus"] == "CREATING", (
        f"precondition: expected the new datastore to still be CREATING, got {before['DatastoreStatus']!r}"
    )
    code, message = _rejected_error(_start_import)
    assert code == "AccessDeniedException", (
        f"expected StartFHIRImportJob against a CREATING datastore to be rejected with AccessDeniedException, got {code!r}: {message!r}"
    )
    expected = "Specified datastore is not active."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    active = _poll_until(
        lambda: healthlake.describe_fhir_datastore(DatastoreId=datastore_id)["DatastoreProperties"],
        lambda p: p["DatastoreStatus"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=2100.0,
        interval_s=20.0,
    )
    assert active["DatastoreStatus"] == "ACTIVE", f"datastore reached {active['DatastoreStatus']}"

    # effect absence: no import job was created by the rejected attempt above. ListFHIRImportJobs
    # itself raises AccessDeniedException("...not active") on a CREATING datastore -- same as
    # StartFHIRImportJob -- so this can only be checked now that the datastore is queryable.
    jobs = healthlake.list_fhir_import_jobs(DatastoreId=datastore_id)["ImportJobPropertiesList"]
    assert jobs == [], f"expected no import jobs from the earlier rejected start, got {jobs!r}"

    # positive control: the identical call succeeds once the datastore is ACTIVE (retrying here past
    # any genuine IAM-propagation delay for the role's first real use).
    started = _retry_on_access_denied(_start_import, timeout_s=90.0)
    assert started["JobStatus"] in ("SUBMITTED", "QUEUED", "IN_PROGRESS"), (
        f"expected the previously-rejected call to be accepted once ACTIVE, got {started['JobStatus']!r}"
    )
    job_id = started["JobId"]

    # independent read: the accepted job is visible in the datastore's own job list.
    jobs_after = healthlake.list_fhir_import_jobs(DatastoreId=datastore_id)["ImportJobPropertiesList"]
    job_ids = {j["JobId"] for j in jobs_after}
    assert job_id in job_ids, f"expected {job_id!r} in the ACTIVE datastore's import job list, got {sorted(job_ids)!r}"

    # terminal read: independent of every response above -- the accepted job actually completes.
    job_props = _poll_until(
        lambda: healthlake.describe_fhir_import_job(DatastoreId=datastore_id, JobId=job_id)["ImportJobProperties"],
        lambda p: p["JobStatus"] in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert job_props["JobStatus"] == "COMPLETED", (
        f"import job ended as {job_props['JobStatus']}: {job_props.get('Message')}"
    )


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchBucket",
            "NoSuchEntity",
            "NotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _rejected_error(fn):
    """Call fn(); return (code, message) from the ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        f"expected StartFHIRImportJob against a CREATING datastore to be rejected, but it succeeded: {result!r}"
    )


def _retry_on_access_denied(fn, *, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"still AccessDenied after {timeout_s}s (IAM propagation?): {last_exc}")


def _empty_and_delete_bucket(s3_client, bucket):
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objects = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
        if objects:
            failed = s3_client.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3_client.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
