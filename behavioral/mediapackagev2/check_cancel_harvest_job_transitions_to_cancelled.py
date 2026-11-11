"""cancel-harvest-job-transitions-to-cancelled."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "cancel-harvest-job-transitions-to-cancelled"
GROUP = "state"
SERVICES = ["mediapackagev2"]


def _grant_harvester_endpoint_access(ctx, mp, group, channel, endpoint, endpoint_arn):
    # MediaPackage v2 requires the origin endpoint to grant the MediaPackage harvester
    # GetObject/HarvestObject access before CreateHarvestJob will queue a job.
    # https://docs.aws.amazon.com/mediapackage/latest/userguide/endpoint-auth.html#mediapackage-endpoint
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Id": "MediaPackageHarvesterAccessPolicy",
            "Statement": [
                {
                    "Sid": "AllowMediaPackageHarvestObjectAccess",
                    "Effect": "Allow",
                    "Principal": {"Service": "mediapackagev2.amazonaws.com"},
                    "Condition": {"StringEquals": {"AWS:SourceAccount": account_id}},
                    "Action": ["mediapackagev2:HarvestObject", "mediapackagev2:GetObject"],
                    "Resource": endpoint_arn,
                }
            ],
        }
    )
    # A freshly created OriginEndpoint can transiently reject its first PutOriginEndpointPolicy
    # with a generic policy-validation error; retry briefly rather than treating it as permanent.
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + 20
    while True:
        try:
            mp.put_origin_endpoint_policy(
                ChannelGroupName=group,
                ChannelName=channel,
                OriginEndpointName=endpoint,
                Policy=policy,
            )
            return
        except ClientError:
            if _time.monotonic() >= deadline:
                raise
            _time.sleep(2)


def _create_harvest_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-mpkg-harvest-").replace("_", "-")
    kwargs = {"Bucket": bucket}
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _empty_and_delete_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete_bucket)
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"Service":"mediapackagev2.amazonaws.com"},'
            '"Action":["s3:PutObject","s3:ListBucket","s3:GetBucketLocation"],'
            f'"Resource":["arn:aws:s3:::{bucket}","arn:aws:s3:::{bucket}/*"]}}]}}'
        ),
    )
    return bucket


def _create_harvest_job_with_retry(mp, **kwargs):
    """S3 bucket-policy grants for the harvester can take a few seconds to propagate;
    retry CreateHarvestJob briefly on the resulting transient S3-access ValidationException
    rather than treating it as a permanent rejection."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + 60
    last_exc = None
    while _time.monotonic() < deadline:
        try:
            return mp.create_harvest_job(**kwargs)
        except ClientError as e:
            msg = e.response["Error"].get("Message", "")
            if e.response["Error"]["Code"] == "ValidationException" and "s3" in msg.lower():
                last_exc = e
                _time.sleep(5)
                continue
            raise
    raise last_exc


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelHarvestJob, called shortly after CreateHarvestJob, transitions the job's
    Status from QUEUED/IN_PROGRESS to CANCELLED, which GetHarvestJob reflects on a
    bounded poll."""
    mp = ctx.client("mediapackagev2")
    group = ctx.unique_name("sim2real-mpkg-cg-")
    channel = ctx.unique_name("sim2real-mpkg-ch-")
    endpoint = ctx.unique_name("sim2real-mpkg-oe-")
    mp.create_channel_group(ChannelGroupName=group, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))
    mp.create_channel(ChannelGroupName=group, ChannelName=channel, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=channel))
    endpoint_created = mp.create_origin_endpoint(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
        )
    )
    _grant_harvester_endpoint_access(ctx, mp, group, channel, endpoint, endpoint_created["Arn"])
    bucket = _create_harvest_bucket(ctx)

    now = datetime.now(timezone.utc)
    job_name = ctx.unique_name("sim2real-mpkg-hj-")
    created = _create_harvest_job_with_retry(
        mp,
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        HarvestJobName=job_name,
        HarvestedManifests={"HlsManifests": [{"ManifestName": "index"}]},
        ScheduleConfiguration={
            "StartTime": now - timedelta(minutes=10),
            "EndTime": now - timedelta(minutes=5),
        },
        Destination={"S3Destination": {"BucketName": bucket, "DestinationPath": "job"}},
    )
    assert created["Status"] in ("QUEUED", "IN_PROGRESS"), (
        f"expected QUEUED or IN_PROGRESS right after CreateHarvestJob, saw {created['Status']!r}"
    )

    mp.cancel_harvest_job(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        HarvestJobName=job_name,
    )

    deadline = time.monotonic() + 30
    status = None
    while time.monotonic() < deadline:
        status = mp.get_harvest_job(
            ChannelGroupName=group,
            ChannelName=channel,
            OriginEndpointName=endpoint,
            HarvestJobName=job_name,
        )["Status"]
        if status == "CANCELLED":
            break
        time.sleep(1.0)
    assert status == "CANCELLED", f"expected CANCELLED, saw {status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
