"""create-harvest-job-invalid-time-range-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-harvest-job-invalid-time-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackage"]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with: {result!r}")


def _create_channel_and_endpoint(ctx):
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-hjnch-")
    mp.create_channel(Id=channel_id)
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    origin_id = ctx.unique_name("sim2real-mp-hjnoe-")
    mp.create_origin_endpoint(
        Id=origin_id, ChannelId=channel_id, HlsPackage={}, StartoverWindowSeconds=86400
    )

    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=origin_id))
    return channel_id, origin_id


def _create_harvest_prereqs(ctx):
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-mp-hjnbucket-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    role_name = ctx.unique_name("sim2real-mp-hjnrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "mediapackage.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-mp-hjnpolicy"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:PutObjectAcl", "s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return {"bucket": bucket, "role_arn": role_arn}


def _create_harvest_job_with_retry(mp, timeout_s=90.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return mp.create_harvest_job(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code == "ForbiddenException" or (
                code == "UnprocessableEntityException" and "assumable" in message.lower()
            ):
                last_exc = e
                time.sleep(5)
                continue
            raise

    raise last_exc


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateHarvestJob with EndTime <= StartTime is rejected with
    UnprocessableEntityException, no job is persisted under that Id, and the exact
    same request with a corrected (valid) time range succeeds (positive control)."""
    mp = ctx.client("mediapackage")

    channel_id, origin_id = _create_channel_and_endpoint(ctx)
    prereqs = _create_harvest_prereqs(ctx)

    now = datetime.now(timezone.utc)
    s3_dest = {
        "BucketName": prereqs["bucket"],
        "ManifestKey": "harvested/manifest.m3u8",
        "RoleArn": prereqs["role_arn"],
    }

    bad_job_id = ctx.unique_name("sim2real-mp-hjn-")
    start = now - timedelta(minutes=10)
    end = start - timedelta(minutes=1)  # EndTime before StartTime -> invalid
    code, message = _error_code(
        lambda: mp.create_harvest_job(
            Id=bad_job_id,
            OriginEndpointId=origin_id,
            StartTime=start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            EndTime=end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            S3Destination=s3_dest,
        )
    )
    assert code == "UnprocessableEntityException", f"expected UnprocessableEntityException, got {code!r}"
    expected_message = "endTime must be later than the start time"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no harvest job was persisted under the rejected Id
    absent_code, absent_message = _error_code(lambda: mp.describe_harvest_job(Id=bad_job_id))
    assert absent_code == "NotFoundException", (
        f"expected NotFoundException for the rejected job id, got {absent_code!r}"
    )
    expected_absent = f"harvestJob with id={bad_job_id} not found"
    assert absent_message == expected_absent, (
        f"expected message {expected_absent!r}, got {absent_message!r}"
    )

    # positive control: same setup, corrected time order succeeds
    good_job_id = ctx.unique_name("sim2real-mp-hjn-")
    good_start = now - timedelta(minutes=10)
    good_end = now - timedelta(minutes=5)
    created = _create_harvest_job_with_retry(
        mp,
        Id=good_job_id,
        OriginEndpointId=origin_id,
        StartTime=good_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        EndTime=good_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        S3Destination=s3_dest,
    )
    assert created["Id"] == good_job_id, f"expected Id {good_job_id!r}, got {created.get('Id')!r}"
    assert created["Status"] == "IN_PROGRESS", (
        f"expected create response Status IN_PROGRESS, got {created.get('Status')!r}"
    )

    # terminal read independent of the mutating call: the corrected job is
    # actually persisted and visible through DescribeHarvestJob, not just echoed
    # back in the create response.
    described = mp.describe_harvest_job(Id=good_job_id)
    assert described["Id"] == good_job_id, f"expected described Id {good_job_id!r}, got {described.get('Id')!r}"
    assert described["ChannelId"] == channel_id, (
        f"expected described ChannelId {channel_id!r}, got {described.get('ChannelId')!r}"
    )
    assert described["OriginEndpointId"] == origin_id, (
        f"expected described OriginEndpointId {origin_id!r}, got {described.get('OriginEndpointId')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
