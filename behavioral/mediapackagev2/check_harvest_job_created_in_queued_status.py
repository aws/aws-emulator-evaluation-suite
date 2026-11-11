"""harvest-job-created-in-queued-status."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "harvest-job-created-in-queued-status"
GROUP = "state"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateHarvestJob on a real channel, origin endpoint and S3 destination returns Status QUEUED, and an
    immediate GetHarvestJob shows it QUEUED or IN_PROGRESS (a window already in the past can start within
    seconds), never terminal or missing."""
    mp = ctx.client("mediapackagev2")
    prereqs = _create_harvest_prereqs(ctx)

    # MediaPackage v2 requires the harvest window to be entirely in the past
    # (https://docs.aws.amazon.com/mediapackage/latest/userguide/live-to-vod.html#live-to-vod-requirements).
    start = datetime.now(timezone.utc) - timedelta(minutes=10)
    end = start + timedelta(minutes=5)
    job_name = ctx.unique_name("sim2real-mpv2-hj-")
    resp = mp.create_harvest_job(
        ChannelGroupName=prereqs["group"],
        ChannelName=prereqs["channel"],
        OriginEndpointName=prereqs["endpoint"],
        HarvestJobName=job_name,
        HarvestedManifests={"HlsManifests": [{"ManifestName": "index"}]},
        ScheduleConfiguration={"StartTime": start, "EndTime": end},
        Destination={
            "S3Destination": {"BucketName": prereqs["bucket"], "DestinationPath": "harvest/"}
        },
    )
    ctx.on_cleanup(
        lambda: _best_effort_cancel(
            mp, prereqs["group"], prereqs["channel"], prereqs["endpoint"], job_name
        )
    )

    assert resp["Status"] == "QUEUED", f"expected QUEUED, got {resp['Status']}"

    got = mp.get_harvest_job(
        ChannelGroupName=prereqs["group"],
        ChannelName=prereqs["channel"],
        OriginEndpointName=prereqs["endpoint"],
        HarvestJobName=job_name,
    )
    assert got["Status"] in ("QUEUED", "IN_PROGRESS"), (
        f"expected the harvest job to still be live (QUEUED or IN_PROGRESS) on an immediate "
        f"independent GetHarvestJob, got {got['Status']}"
    )


def _create_harvest_prereqs(ctx) -> dict[str, str]:
    mp = ctx.client("mediapackagev2")
    s3 = ctx.client("s3")

    group = ctx.unique_name("sim2real-mpv2-cg-")
    mp.create_channel_group(ChannelGroupName=group)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))

    channel = ctx.unique_name("sim2real-mpv2-ch-")
    mp.create_channel(ChannelGroupName=group, ChannelName=channel)
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=channel))

    endpoint = ctx.unique_name("sim2real-mpv2-oe-")
    endpoint_created = mp.create_origin_endpoint(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index", "ManifestWindowSeconds": 60}],
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


def _best_effort_cancel(mp, group: str, channel: str, endpoint: str, job_name: str) -> None:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
