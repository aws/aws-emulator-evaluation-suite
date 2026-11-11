"""harvest-job-provisioning-end-to-end-workflow."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "harvest-job-provisioning-end-to-end-workflow"
GROUP = "e2e"
SERVICES = ["mediapackage"]


def _create_channel_and_endpoint(ctx):
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-hjch-")
    mp.create_channel(Id=channel_id, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    origin_id = ctx.unique_name("sim2real-mp-hjoe-")
    mp.create_origin_endpoint(
        Id=origin_id,
        ChannelId=channel_id,
        HlsPackage={},
        StartoverWindowSeconds=86400,
        Tags={"sim2real": CHECK},
    )

    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=origin_id))
    return channel_id, origin_id


def _create_harvest_prereqs(ctx):
    """Real S3 bucket + IAM role trusted by mediapackage.amazonaws.com, so
    CreateHarvestJob's synchronous role-assumability check can pass."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-mp-hjbucket-")
    if ctx.region == "us-east-1":  # S3 CreateBucket rejects a LocationConstraint for us-east-1 itself
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    role_name = ctx.unique_name("sim2real-mp-hjrole-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-mp-hjpolicy"
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
    """IAM role trust can take a few seconds to propagate; retry while MediaPackage
    reports the role as not yet assumable (either ForbiddenException or an
    UnprocessableEntityException whose message names assumability)."""
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateHarvestJob with a valid window, a real origin endpoint and an assumable role returns
    IN_PROGRESS, and its ids, channel, endpoint and S3 destination agree across the create response,
    DescribeHarvestJob and a channel-filtered ListHarvestJobs."""
    mp = ctx.client("mediapackage")

    channel_id, origin_id = _create_channel_and_endpoint(ctx)
    prereqs = _create_harvest_prereqs(ctx)

    job_id = ctx.unique_name("sim2real-mp-hj-")
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=10)
    end = now - timedelta(minutes=5)
    s3_dest = {
        "BucketName": prereqs["bucket"],
        "ManifestKey": "harvested/manifest.m3u8",
        "RoleArn": prereqs["role_arn"],
    }

    created = _create_harvest_job_with_retry(
        mp,
        Id=job_id,
        OriginEndpointId=origin_id,
        StartTime=start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        EndTime=end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        S3Destination=s3_dest,
    )

    assert created["Id"] == job_id
    assert created["OriginEndpointId"] == origin_id
    assert created["ChannelId"] == channel_id
    assert created["Status"] == "IN_PROGRESS"
    assert created["S3Destination"]["BucketName"] == prereqs["bucket"]

    described = mp.describe_harvest_job(Id=job_id)
    assert described["Id"] == job_id
    assert described["ChannelId"] == channel_id
    assert described["OriginEndpointId"] == origin_id
    assert described["S3Destination"]["ManifestKey"] == "harvested/manifest.m3u8"

    listed = mp.list_harvest_jobs(IncludeChannelId=channel_id)["HarvestJobs"]
    listed_ids = [j["Id"] for j in listed]
    assert job_id in listed_ids, f"expected {job_id} in channel-filtered ListHarvestJobs, got {listed_ids}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
