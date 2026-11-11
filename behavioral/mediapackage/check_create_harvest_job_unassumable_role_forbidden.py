"""create-harvest-job-unassumable-role-forbidden."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-harvest-job-unassumable-role-forbidden"
GROUP = "overly-permissive"
SERVICES = ["mediapackage"]


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateHarvestJob with an S3Destination RoleArn that mediapackage.amazonaws.com cannot assume fails
    UnprocessableEntityException with the exact message at create time and no job exists afterwards,
    while the same request with a role that trusts MediaPackage creates a describable, listed job."""
    mp = ctx.client("mediapackage")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-mp-harvest-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    # A role that exists but trusts only S3 (not MediaPackage) -- syntactically
    # valid ARN, but MediaPackage cannot assume it.
    wrong_role_name = ctx.unique_name("sim2real-mp-wrong-trust-role-")
    wrong_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    wrong_role = iam.create_role(
        RoleName=wrong_role_name,
        AssumeRolePolicyDocument=json.dumps(wrong_trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    wrong_role_arn = wrong_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=wrong_role_name))

    channel_id = ctx.unique_name("sim2real-mp-chan-")
    mp.create_channel(Id=channel_id, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))
    endpoint_id = ctx.unique_name("sim2real-mp-ep-")
    mp.create_origin_endpoint(
        Id=endpoint_id,
        ChannelId=channel_id,
        HlsPackage={"SegmentDurationSeconds": 6},
        StartoverWindowSeconds=3600,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=endpoint_id))

    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=10)
    end = now - timedelta(minutes=5)

    bad_job_id = ctx.unique_name("sim2real-mp-hj-bad-")
    code, message = _error_code(
        lambda: mp.create_harvest_job(
            Id=bad_job_id,
            OriginEndpointId=endpoint_id,
            StartTime=start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            EndTime=end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            S3Destination={
                "BucketName": bucket,
                "ManifestKey": "bad/index.m3u8",
                "RoleArn": wrong_role_arn,
            },
        )
    )
    assert code == "UnprocessableEntityException", f"unexpected error code: {code!r}"
    expected_message = (
        "s3Destination.roleArn must be assumable by MediaPackage. Please ensure that its trust "
        "policy includes mediapackage.amazonaws.com"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    absent_code, absent_message = _error_code(lambda: mp.describe_harvest_job(Id=bad_job_id))
    assert absent_code == "NotFoundException", "a HarvestJob record leaked despite the rejected create"
    expected_absent = f"harvestJob with id={bad_job_id} not found"
    assert absent_message == expected_absent, (
        f"expected message {expected_absent!r}, got {absent_message!r}"
    )

    # Positive control: an identical request but with a role that DOES trust
    # MediaPackage succeeds.
    good_role_name = ctx.unique_name("sim2real-mp-good-trust-role-")
    good_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "mediapackage.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    good_role = iam.create_role(
        RoleName=good_role_name,
        AssumeRolePolicyDocument=json.dumps(good_trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    good_role_arn = good_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))
    iam.put_role_policy(
        RoleName=good_role_name,
        PolicyName="harvest-s3-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"],
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=good_role_name, PolicyName="harvest-s3-write")
    )

    good_job_id = ctx.unique_name("sim2real-mp-hj-good-")
    created = _create_harvest_job_with_retry(
        lambda: mp.create_harvest_job(
            Id=good_job_id,
            OriginEndpointId=endpoint_id,
            StartTime=start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            EndTime=end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            S3Destination={
                "BucketName": bucket,
                "ManifestKey": "good/index.m3u8",
                "RoleArn": good_role_arn,
            },
        )
    )
    assert created["Id"] == good_job_id, f"expected create response Id {good_job_id!r}, got {created['Id']!r}"

    # Terminal assertion is an independent read, at the destination, through a
    # different operation than the one that mutated.
    described = mp.describe_harvest_job(Id=good_job_id)
    assert described["Id"] == good_job_id
    assert described["S3Destination"]["RoleArn"] == good_role_arn

    listed_ids = {job["Id"] for job in mp.list_harvest_jobs(IncludeChannelId=channel_id)["HarvestJobs"]}
    assert good_job_id in listed_ids, f"expected {good_job_id!r} in ListHarvestJobs, got {listed_ids!r}"


def _create_harvest_job_with_retry(fn, *, attempts: int = 6, delay_seconds: float = 5.0):
    import time

    from botocore.exceptions import ClientError

    last_error = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code in ("UnprocessableEntityException", "ForbiddenException") and (
                "assumable" in message.lower() or "assume" in message.lower()
            ):
                last_error = e
                if attempt < attempts - 1:
                    time.sleep(delay_seconds)
                continue
            raise
    raise last_error


def _delete_bucket(ctx, bucket: str) -> None:
    from botocore.exceptions import ClientError

    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
