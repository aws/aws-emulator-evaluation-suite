"""start-transformation-job-nonexistent-profile-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-transformation-job-nonexistent-profile-not-found"
GROUP = "error-semantics"
SERVICES = ["healthlake"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartDataTransformationJob rejects a ProfileId that does not exist with ResourceNotFoundException,
    once the S3 input/output locations themselves are valid (isolating the profile-lookup boundary)."""
    healthlake = ctx.client("healthlake")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    sts.get_caller_identity()["Account"]

    in_bucket = ctx.unique_name("sim2real-behav-dtj-in")
    out_bucket = ctx.unique_name("sim2real-behav-dtj-out")
    _create_bucket(s3, in_bucket, ctx.region)
    ctx.on_cleanup(lambda: _delete_bucket(s3, in_bucket))
    _create_bucket(s3, out_bucket, ctx.region)
    ctx.on_cleanup(lambda: _delete_bucket(s3, out_bucket))
    s3.put_object(Bucket=in_bucket, Key="input.csv", Body=b"PAT_ID\nP1\n")
    s3.put_object(Bucket=in_bucket, Key="input.xml", Body=b"<ClinicalDocument/>")

    # a real, published profile — used only for the positive control below, never
    # for the rejected call, so the boundary under test stays the ProfileId lookup.
    profile_name = ctx.unique_name("sim2real-profile-")
    created_profile = healthlake.create_data_transformation_profile(
        SourceFormat="CCDA",
        ProfileName=profile_name,
        Source={"ProfileMapping": {"ProfileMapping": {"Resources/Patient.vm": "content"}}},
    )
    real_profile_id = created_profile["ProfileId"]
    ctx.on_cleanup(
        lambda: healthlake.delete_data_transformation_profile(ProfileId=real_profile_id)
    )
    healthlake.publish_data_transformation_profile(ProfileId=real_profile_id, SourceFormat="CCDA")

    role_name = ctx.unique_name("sim2real-behav-dtj-role")
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
    import json

    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))

    s3_access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{in_bucket}", f"arn:aws:s3:::{in_bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{out_bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["kms:DescribeKey", "kms:GenerateDataKey", "kms:Decrypt"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3access", PolicyDocument=json.dumps(s3_access_policy)
    )
    ctx.on_cleanup(
        lambda: _best_effort(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3access"))
    )

    bogus_profile_id = "0" * 32

    rejected_job_name = ctx.unique_name("sim2real-dtj-noprofile-")
    accepted_job_name = ctx.unique_name("sim2real-dtj-profile-")

    def _start_job(profile_id, key, source_format, job_name):
        return healthlake.start_data_transformation_job(
            JobName=job_name,
            InputDataConfig={"S3Uri": f"s3://{in_bucket}/{key}", "SourceFormat": source_format},
            OutputDataConfig={
                "S3Configuration": {
                    "S3Uri": f"s3://{out_bucket}/output/",
                    "KmsKeyId": "alias/aws/s3",
                }
            },
            DataAccessRoleArn=role_arn,
            ClientToken=ctx.unique_name("sim2real-token-"),
            ProfileId=profile_id,
        )

    # bound the call with a short retry against transient AccessDenied from IAM
    # policy-propagation lag, so we reach the actual profile-lookup boundary under test.
    import time

    deadline = time.monotonic() + 60.0
    code, message = None, None
    while time.monotonic() < deadline:
        code, message = _error_code_and_message(
            lambda: _start_job(bogus_profile_id, "input.csv", "CSV", rejected_job_name)
        )
        if code != "AccessDeniedException":
            break
        time.sleep(5.0)
    assert code == "ResourceNotFoundException", f"DIAG code={code} msg={message}"
    expected_message = f"Data transformation profile not found: {bogus_profile_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absence: the rejected submission created no job, seen from an
    # independent read rather than trusting the mutating call's own exception.
    jobs_after_rejection = healthlake.list_data_transformation_jobs(JobName=rejected_job_name)["Items"]
    assert jobs_after_rejection == [], (
        f"rejected StartDataTransformationJob should create no job named {rejected_job_name!r}: "
        f"{jobs_after_rejection!r}"
    )

    # positive control: the identical wiring (role, buckets, KMS key) accepts a
    # real ProfileId, so the rejection above is specific to the bogus profile and
    # not a symptom of every StartDataTransformationJob call failing in this account.
    started = None
    last_code, last_message = None, None
    deadline_started = time.monotonic() + 90.0
    while time.monotonic() < deadline_started:
        try:
            started = _start_job(real_profile_id, "input.xml", "CCDA", accepted_job_name)
            break
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            last_message = exc.response["Error"]["Message"]
            if last_code not in ("AccessDeniedException", "ValidationException"):
                raise
            time.sleep(5.0)
    assert started is not None, f"DIAG positive control never accepted: code={last_code} msg={last_message}"

    # terminal read: an INDEPENDENT read (DescribeDataTransformationJob, not the
    # StartDataTransformationJob response we already hold) confirms the accepted
    # job is really visible at the destination, not just echoed back by the mutator.
    described = healthlake.describe_data_transformation_job(JobId=started["JobId"])[
        "TransformationJobProperties"
    ]
    assert described["JobId"] == started["JobId"], (
        f"expected DescribeDataTransformationJob to see JobId={started['JobId']!r}, "
        f"got {described.get('JobId')!r}"
    )
    assert described["JobStatus"] in ("SUBMITTED", "QUEUED", "IN_PROGRESS", "COMPLETED"), (
        f"unexpected JobStatus from an independent read: {described['JobStatus']!r}"
    )


def _create_bucket(s3, name, region):
    if region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": region})


def _delete_bucket(s3, name):
    try:
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
