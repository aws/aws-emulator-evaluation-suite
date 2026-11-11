"""list-harvest-jobs-filters-by-status."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "list-harvest-jobs-filters-by-status"
GROUP = "state"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListHarvestJobs with the Status query filter scopes results to that exact
    HarvestJobStatus: after cancelling a job, it shows up under the CANCELLED filter
    and never under the COMPLETED filter."""
    mp = ctx.client("mediapackagev2")
    prereqs = _create_harvest_prereqs(ctx)

    # MediaPackage v2 requires the harvest window to be entirely in the past
    # (https://docs.aws.amazon.com/mediapackage/latest/userguide/live-to-vod.html#live-to-vod-requirements).
    start = datetime.now(timezone.utc) - timedelta(minutes=10)
    end = start + timedelta(minutes=5)

    job_name = ctx.unique_name("sim2real-mpv2-hj-")
    mp.create_harvest_job(
        ChannelGroupName=prereqs["group"],
        ChannelName=prereqs["channel"],
        OriginEndpointName=prereqs["endpoint"],
        HarvestJobName=job_name,
        HarvestedManifests={"HlsManifests": [{"ManifestName": "index"}]},
        ScheduleConfiguration={"StartTime": start, "EndTime": end},
        Destination={
            "S3Destination": {"BucketName": prereqs["bucket"], "DestinationPath": "j/"}
        },
        Tags={"sim2real": CHECK},
    )
    mp.cancel_harvest_job(
        ChannelGroupName=prereqs["group"],
        ChannelName=prereqs["channel"],
        OriginEndpointName=prereqs["endpoint"],
        HarvestJobName=job_name,
    )

    cancelled_names = {
        j["HarvestJobName"]
        for j in mp.list_harvest_jobs(
            ChannelGroupName=prereqs["group"],
            ChannelName=prereqs["channel"],
            OriginEndpointName=prereqs["endpoint"],
            Status="CANCELLED",
        )["Items"]
    }
    completed_names = {
        j["HarvestJobName"]
        for j in mp.list_harvest_jobs(
            ChannelGroupName=prereqs["group"],
            ChannelName=prereqs["channel"],
            OriginEndpointName=prereqs["endpoint"],
            Status="COMPLETED",
        )["Items"]
    }

    assert job_name in cancelled_names, f"{job_name} missing from CANCELLED filter: {cancelled_names}"
    assert job_name not in completed_names, f"{job_name} leaked into COMPLETED filter"

    # unfiltered listing must also surface it, as CANCELLED is a real terminal status
    all_names = {
        j["HarvestJobName"]
        for j in mp.list_harvest_jobs(
            ChannelGroupName=prereqs["group"],
            ChannelName=prereqs["channel"],
            OriginEndpointName=prereqs["endpoint"],
        )["Items"]
    }
    assert job_name in all_names, f"{job_name} missing from the unfiltered listing: {all_names}"


def _create_harvest_prereqs(ctx) -> dict[str, str]:
    mp = ctx.client("mediapackagev2")
    s3 = ctx.client("s3")

    group = ctx.unique_name("sim2real-mpv2-cg-")
    mp.create_channel_group(ChannelGroupName=group, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))

    channel = ctx.unique_name("sim2real-mpv2-ch-")
    mp.create_channel(ChannelGroupName=group, ChannelName=channel, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=channel))

    endpoint = ctx.unique_name("sim2real-mpv2-oe-")
    endpoint_created = mp.create_origin_endpoint(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index", "ManifestWindowSeconds": 60}],
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
        )
    )

    # CreateHarvestJob validates that the origin endpoint grants the MediaPackage
    # harvester GetObject/HarvestObject access before it will queue a job
    # (https://docs.aws.amazon.com/mediapackage/latest/userguide/endpoint-auth.html#mediapackage-endpoint).
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    endpoint_policy = {
        "Version": "2012-10-17",
        "Id": "MediaPackageHarvesterAccessPolicy",
        "Statement": [
            {
                "Sid": "AllowMediaPackageHarvestObjectAccess",
                "Effect": "Allow",
                "Principal": {"Service": "mediapackagev2.amazonaws.com"},
                "Condition": {"StringEquals": {"AWS:SourceAccount": account_id}},
                "Action": ["mediapackagev2:HarvestObject", "mediapackagev2:GetObject"],
                "Resource": endpoint_created["Arn"],
            }
        ],
    }
    mp.put_origin_endpoint_policy(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        Policy=json.dumps(endpoint_policy),
    )

    bucket = ctx.unique_name("sim2real-mpv2-harvest-").lower().replace("_", "-")
    create_kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    def _cleanup_bucket() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "mediapackagev2.amazonaws.com"},
                "Action": ["s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

    return {"group": group, "channel": channel, "endpoint": endpoint, "bucket": bucket}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
