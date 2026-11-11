"""start-transformation-job-untrusted-role-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-transformation-job-untrusted-role-rejected"
GROUP = "overly-permissive"
SERVICES = ["healthlake"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartDataTransformationJob rejects a DataAccessRoleArn whose trust policy does not allow HealthLake to assume it."""
    healthlake = ctx.client("healthlake")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    kms = ctx.client("kms")

    profile_name = ctx.unique_name("sim2real-profile-")
    created = healthlake.create_data_transformation_profile(
        SourceFormat="CCDA",
        ProfileName=profile_name,
        Source={"ProfileMapping": {"ProfileMapping": {"Resources/Patient.vm": "content"}}},
    )
    profile_id = created["ProfileId"]
    ctx.on_cleanup(lambda: healthlake.delete_data_transformation_profile(ProfileId=profile_id))
    healthlake.publish_data_transformation_profile(ProfileId=profile_id, SourceFormat="CCDA")

    # real S3 locations so the boundary under test is the role's trust policy,
    # not an earlier "bucket does not exist" input-validation failure.
    in_bucket = ctx.unique_name("sim2real-behav-dtj-in")
    out_bucket = ctx.unique_name("sim2real-behav-dtj-out")
    _create_bucket(s3, in_bucket, ctx.region)
    ctx.on_cleanup(lambda: _delete_bucket(s3, in_bucket))
    _create_bucket(s3, out_bucket, ctx.region)
    ctx.on_cleanup(lambda: _delete_bucket(s3, out_bucket))
    s3.put_object(Bucket=in_bucket, Key="input.xml", Body=b"<ClinicalDocument/>")

    # the output encryption key is the check's own customer-managed key
    key_id = kms.create_key(Description="sim2real healthlake transformation output")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # a role that trusts a completely unrelated principal, not healthlake.amazonaws.com
    untrusted_role_name = ctx.unique_name("sim2real-untrusted-role-")
    untrusted_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    untrusted_role_arn = iam.create_role(
        RoleName=untrusted_role_name, AssumeRolePolicyDocument=json.dumps(untrusted_trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=untrusted_role_name)))

    untrusted_job_name = ctx.unique_name("sim2real-dtj-untrusted-")

    def _start_job(role_arn, job_name):
        return healthlake.start_data_transformation_job(
            JobName=job_name,
            InputDataConfig={"S3Uri": f"s3://{in_bucket}/input.xml", "SourceFormat": "CCDA"},
            OutputDataConfig={
                "S3Configuration": {
                    "S3Uri": f"s3://{out_bucket}/output/",
                    "KmsKeyId": key_id,
                }
            },
            DataAccessRoleArn=role_arn,
            ClientToken=ctx.unique_name("sim2real-token-"),
            ProfileId=profile_id,
        )

    code, message = _error(lambda: _start_job(untrusted_role_arn, untrusted_job_name))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    # AWS words this refusal as the caller's iam:PassRole being denied on the untrusted role.
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    expected = (
        f"User: {caller_arn} is not authorized to perform: iam:PassRole on resource: "
        f"{untrusted_role_arn}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absence: the rejected submission created no job under its own name.
    jobs_after_rejection = healthlake.list_data_transformation_jobs(JobName=untrusted_job_name)["Items"]
    assert jobs_after_rejection == [], (
        f"expected no job named {untrusted_job_name!r} after the rejected submission, "
        f"found {jobs_after_rejection!r}"
    )

    # positive control: a role that DOES trust healthlake.amazonaws.com is accepted.
    trusted_role_name = ctx.unique_name("sim2real-trusted-role-")
    trusted_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "healthlake.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    trusted_role_arn = iam.create_role(
        RoleName=trusted_role_name, AssumeRolePolicyDocument=json.dumps(trusted_trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=trusted_role_name)))
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: iam.delete_role_policy(RoleName=trusted_role_name, PolicyName="s3access")
        )
    )
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
        RoleName=trusted_role_name,
        PolicyName="s3access",
        PolicyDocument=json.dumps(s3_access_policy),
    )

    trusted_job_name = ctx.unique_name("sim2real-dtj-trusted-")
    started = None
    last_code = None
    last_msg = None
    deadline_started = __import__("time").monotonic() + 90.0
    while __import__("time").monotonic() < deadline_started:
        try:
            started = _start_job(trusted_role_arn, trusted_job_name)
            break
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            last_msg = exc.response["Error"]["Message"]
            if last_code not in ("AccessDeniedException", "ValidationException"):
                raise
            __import__("time").sleep(5.0)
    assert started is not None, last_msg

    # independent read: the accepted job is visible with the identity it was submitted with
    # (its status is still moving, so it is not graded here).
    job_id = started["JobId"]
    described = healthlake.describe_data_transformation_job(JobId=job_id)[
        "TransformationJobProperties"
    ]
    assert described["JobId"] == job_id, f"expected {job_id}, got {described['JobId']}"
    assert described["JobName"] == trusted_job_name, (
        f"expected JobName {trusted_job_name!r}, got {described.get('JobName')!r}"
    )
    assert described["DataAccessRoleArn"] == trusted_role_arn, (
        f"expected DataAccessRoleArn {trusted_role_arn!r}, got {described.get('DataAccessRoleArn')!r}"
    )
    assert described["ProfileId"] == profile_id, (
        f"expected ProfileId {profile_id!r}, got {described.get('ProfileId')!r}"
    )


def _create_bucket(s3, name, region):
    # not a region pin: CreateBucket's own API quirk is that us-east-1 rejects a
    # LocationConstraint, so this branches on ctx.region's value rather than hardcoding it.
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


def _error(fn):
    """Call fn(); return its ClientError (code, message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
