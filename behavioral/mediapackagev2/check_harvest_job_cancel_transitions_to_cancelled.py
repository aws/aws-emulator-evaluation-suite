"""harvest-job-cancel-transitions-to-cancelled."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "harvest-job-cancel-transitions-to-cancelled"
GROUP = "state"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelHarvestJob moves a QUEUED harvest job's status to CANCELLED, observed via GetHarvestJob."""
    mp = ctx.client("mediapackagev2")
    s3 = ctx.client("s3")

    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    endpoint_name = ctx.unique_name("sim2real-mpv2-oe-")
    job_name = ctx.unique_name("sim2real-mpv2-hj-")
    bucket_name = ctx.unique_name("sim2real-mpv2-harvest-")

    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_name, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))
    endpoint_created = mp.create_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
        )
    )
    _create_bucket(ctx, s3, bucket_name)
    _grant_harvester_endpoint_access(
        ctx, mp, group_name, channel_name, endpoint_name, endpoint_created["Arn"]
    )

    now = datetime.now(timezone.utc)
    created = mp.create_harvest_job(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        HarvestJobName=job_name,
        HarvestedManifests={"HlsManifests": [{"ManifestName": "index"}]},
        ScheduleConfiguration={
            "StartTime": now + timedelta(minutes=10),
            "EndTime": now + timedelta(minutes=15),
        },
        Destination={"S3Destination": {"BucketName": bucket_name, "DestinationPath": "harvested"}},
        Tags={"sim2real": CHECK},
    )
    assert created["HarvestJobName"] == job_name, (
        f"expected CreateHarvestJob to echo back {job_name!r}, got {created['HarvestJobName']!r}"
    )
    assert created["Status"] == "QUEUED", f"expected a freshly created harvest job to be QUEUED, got {created['Status']!r}"

    mp.cancel_harvest_job(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name, HarvestJobName=job_name
    )

    final_status = _poll_until(
        lambda: mp.get_harvest_job(
            ChannelGroupName=group_name,
            ChannelName=channel_name,
            OriginEndpointName=endpoint_name,
            HarvestJobName=job_name,
        )["Status"],
        predicate=lambda s: s == "CANCELLED",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert final_status == "CANCELLED", f"expected CancelHarvestJob to drive Status to CANCELLED, saw {final_status!r}"


def _create_bucket(ctx, s3, bucket_name: str) -> None:
    kwargs = {"Bucket": bucket_name}
    # us-east-1 is CreateBucket's own default region; passing a LocationConstraint
    # for it is rejected with InvalidLocationConstraint, so it must be omitted only there.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"Service":"mediapackagev2.amazonaws.com"},'
            '"Action":["s3:PutObject","s3:ListBucket","s3:GetBucketLocation"],'
            f'"Resource":["arn:aws:s3:::{bucket_name}","arn:aws:s3:::{bucket_name}/*"]}}]}}'
        ),
    )


def _grant_harvester_endpoint_access(ctx, mp, group, channel, endpoint, endpoint_arn) -> None:
    # CreateHarvestJob validates that the origin endpoint grants the MediaPackage
    # harvester GetObject/HarvestObject access before it will queue a job.
    # https://docs.aws.amazon.com/mediapackage/latest/userguide/endpoint-auth.html#mediapackage-endpoint
    import json as _json

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    mp.put_origin_endpoint_policy(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        Policy=_json.dumps(
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


def _empty_and_delete_bucket(s3, bucket_name: str) -> None:
    resp = s3.list_objects_v2(Bucket=bucket_name)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket_name)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
