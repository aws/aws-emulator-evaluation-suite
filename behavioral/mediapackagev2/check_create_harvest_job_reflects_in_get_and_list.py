"""create-harvest-job-reflects-in-get-and-list."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-harvest-job-reflects-in-get-and-list"
GROUP = "state"
SERVICES = ["mediapackagev2"]


def _grant_harvester_endpoint_access(ctx, mp, group, channel, endpoint, endpoint_arn):
    # MediaPackage v2 requires the origin endpoint to grant the MediaPackage harvester
    # GetObject/HarvestObject access before CreateHarvestJob will queue a job.
    # https://docs.aws.amazon.com/mediapackage/latest/userguide/endpoint-auth.html#mediapackage-endpoint
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    mp.put_origin_endpoint_policy(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        Policy=json.dumps(
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
        ),
    )


def _create_harvest_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-mpkg-harvest-").replace("_", "-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _empty_and_delete_bucket() -> None:
        # A harvest job can land objects under the destination path even when the
        # window has no source content; delete_bucket fails BucketNotEmpty if we don't
        # clear those first.
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete_bucket)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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

    deadline = _time.monotonic() + 90
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created HarvestJob's Destination/ScheduleConfiguration/HarvestedManifests are
    returned verbatim by GetHarvestJob and the job appears in ListHarvestJobs scoped to
    the same channel and origin endpoint."""
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
    start_time = now - timedelta(minutes=10)
    end_time = now - timedelta(minutes=5)
    job_name = ctx.unique_name("sim2real-mpkg-hj-")
    _create_harvest_job_with_retry(
        mp,
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        HarvestJobName=job_name,
        Description="behavioral round-trip",
        HarvestedManifests={"HlsManifests": [{"ManifestName": "index"}]},
        ScheduleConfiguration={"StartTime": start_time, "EndTime": end_time},
        Destination={"S3Destination": {"BucketName": bucket, "DestinationPath": "roundtrip"}},
        Tags={"sim2real": CHECK},
    )

    def _cancel_best_effort():
        from botocore.exceptions import ClientError

        try:
            mp.cancel_harvest_job(
                ChannelGroupName=group,
                ChannelName=channel,
                OriginEndpointName=endpoint,
                HarvestJobName=job_name,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cancel_best_effort)

    got = mp.get_harvest_job(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        HarvestJobName=job_name,
    )
    assert got["Description"] == "behavioral round-trip", (
        f"expected Description 'behavioral round-trip', got {got['Description']!r}"
    )
    assert got["Destination"]["S3Destination"]["BucketName"] == bucket, (
        f"expected destination bucket {bucket!r}, "
        f"got {got['Destination']['S3Destination']['BucketName']!r}"
    )
    assert got["Destination"]["S3Destination"]["DestinationPath"] == "roundtrip", (
        "expected destination path 'roundtrip', "
        f"got {got['Destination']['S3Destination']['DestinationPath']!r}"
    )
    assert got["HarvestedManifests"]["HlsManifests"][0]["ManifestName"] == "index", (
        f"expected HLS manifest name 'index', got {got['HarvestedManifests']['HlsManifests']!r}"
    )
    got_start = got["ScheduleConfiguration"]["StartTime"].replace(microsecond=0)
    want_start = start_time.replace(microsecond=0)
    assert got_start == want_start, f"expected StartTime {want_start!r}, got {got_start!r}"
    got_end = got["ScheduleConfiguration"]["EndTime"].replace(microsecond=0)
    want_end = end_time.replace(microsecond=0)
    assert got_end == want_end, f"expected EndTime {want_end!r}, got {got_end!r}"

    listed = mp.list_harvest_jobs(
        ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
    )["Items"]
    names = {item["HarvestJobName"] for item in listed}
    assert job_name in names, f"expected {job_name!r} in ListHarvestJobs, got names {names!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
