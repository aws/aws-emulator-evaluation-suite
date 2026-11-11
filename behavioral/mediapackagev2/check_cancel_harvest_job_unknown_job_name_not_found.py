"""cancel-harvest-job-unknown-job-name-not-found."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from behavioral_harness import tags

CHECK = "cancel-harvest-job-unknown-job-name-not-found"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelHarvestJob on a never-created HarvestJobName under a real channel group, channel and endpoint
    fails ResourceNotFoundException with the exact message; a real job cancelled earlier keeps CANCELLED
    and its ETag, and the bogus name never appears in ListHarvestJobs."""
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
            "S3Destination": {"BucketName": prereqs["bucket"], "DestinationPath": "harvest/"}
        },
    )

    # positive control: cancelling a live QUEUED job succeeds
    mp.cancel_harvest_job(
        ChannelGroupName=prereqs["group"],
        ChannelName=prereqs["channel"],
        OriginEndpointName=prereqs["endpoint"],
        HarvestJobName=job_name,
    )
    cancelled = _poll_until(
        probe=lambda: mp.get_harvest_job(
            ChannelGroupName=prereqs["group"],
            ChannelName=prereqs["channel"],
            OriginEndpointName=prereqs["endpoint"],
            HarvestJobName=job_name,
        ),
        predicate=lambda job: job["Status"] == "CANCELLED",
        timeout_s=60,
        interval_s=2,
    )
    etag_after_first_cancel = cancelled["ETag"]

    # break: cancel a HarvestJobName that was never created under this same,
    # real parent chain
    bogus_job_name = ctx.unique_name("sim2real-mpv2-hj-bogus-")
    err = _client_error(
        lambda: mp.cancel_harvest_job(
            ChannelGroupName=prereqs["group"],
            ChannelName=prereqs["channel"],
            OriginEndpointName=prereqs["endpoint"],
            HarvestJobName=bogus_job_name,
        )
    )
    assert err is not None, "expected cancelling an unknown HarvestJobName to fail"
    assert err.response["Error"]["Code"] == "ResourceNotFoundException", err.response
    expected_message = (
        "MediaPackage can't process your request because we can't find your harvest job. "
        "Verify your harvest job id or create a harvest job and then try again"
    )
    assert err.response["Error"]["Message"] == expected_message, err.response

    # effect absent: the real job's status/etag are untouched, and the bogus name
    # never shows up in the listing
    still = mp.get_harvest_job(
        ChannelGroupName=prereqs["group"],
        ChannelName=prereqs["channel"],
        OriginEndpointName=prereqs["endpoint"],
        HarvestJobName=job_name,
    )
    assert still["Status"] == "CANCELLED", f"expected CANCELLED, got {still['Status']!r}"
    assert still["ETag"] == etag_after_first_cancel, (
        f"ETag changed after rejected cancel of unknown job: "
        f"expected {etag_after_first_cancel!r}, got {still['ETag']!r}"
    )

    names = {
        j["HarvestJobName"]
        for j in mp.list_harvest_jobs(
            ChannelGroupName=prereqs["group"],
            ChannelName=prereqs["channel"],
            OriginEndpointName=prereqs["endpoint"],
        )["Items"]
    }
    assert bogus_job_name not in names, f"bogus job {bogus_job_name} appeared in listing"


def _create_harvest_prereqs(ctx) -> dict[str, str]:
    mp = ctx.client("mediapackagev2")
    s3 = ctx.client("s3")

    group = ctx.unique_name("sim2real-mpv2-cg-")
    mp.create_channel_group(ChannelGroupName=group, Tags={"purpose": "behavioral"})
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


def _client_error(fn: Callable[[], Any]) -> Optional[Any]:
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as e:
        return e


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
