"""create-harvest-job-end-time-before-start-time-rejected."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-harvest-job-end-time-before-start-time-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateHarvestJob with EndTime earlier than StartTime is rejected with
    ValidationException(END_TIME_EARLIER_THAN_START_TIME), no job is created, and a
    request with a valid StartTime < EndTime schedule succeeds (positive control)."""
    mp = ctx.client("mediapackagev2")
    prereqs = _create_harvest_prereqs(ctx)

    # MediaPackage v2 requires the harvest window to be entirely in the past
    # (https://docs.aws.amazon.com/mediapackage/latest/userguide/live-to-vod.html#live-to-vod-requirements).
    start = datetime.now(timezone.utc) - timedelta(minutes=10)
    bad_end = start - timedelta(minutes=5)
    bad_job_name = ctx.unique_name("sim2real-mpv2-hj-bad-")

    err = _client_error(
        lambda: mp.create_harvest_job(
            ChannelGroupName=prereqs["group"],
            ChannelName=prereqs["channel"],
            OriginEndpointName=prereqs["endpoint"],
            HarvestJobName=bad_job_name,
            HarvestedManifests={"HlsManifests": [{"ManifestName": "index"}]},
            ScheduleConfiguration={"StartTime": start, "EndTime": bad_end},
            Destination={
                "S3Destination": {"BucketName": prereqs["bucket"], "DestinationPath": "bad/"}
            },
        )
    )
    assert err is not None, "expected EndTime < StartTime to be rejected"
    assert err.response["Error"]["Code"] == "ValidationException", (
        f"expected ValidationException, got {err.response['Error']['Code']}"
    )
    expected_message = (
        "Validation error encountered at request.scheduleConfiguration: Harvest job end time "
        "must be later than the start time. Check your configured start and end times and "
        "then try again"
    )
    assert err.response["Error"]["Message"] == expected_message, err.response
    actual_type = err.response.get("ValidationExceptionType")
    assert actual_type == "END_TIME_EARLIER_THAN_START_TIME", (
        f"expected ValidationExceptionType END_TIME_EARLIER_THAN_START_TIME, got {actual_type}"
    )

    # effect absent: no job with that name exists
    names = {
        j["HarvestJobName"]
        for j in mp.list_harvest_jobs(
            ChannelGroupName=prereqs["group"],
            ChannelName=prereqs["channel"],
            OriginEndpointName=prereqs["endpoint"],
        )["Items"]
    }
    assert bad_job_name not in names, f"rejected job {bad_job_name} was created anyway"

    # positive control: a valid schedule (StartTime < EndTime) succeeds
    good_job_name = ctx.unique_name("sim2real-mpv2-hj-good-")
    good_end = start + timedelta(minutes=5)
    created = mp.create_harvest_job(
        ChannelGroupName=prereqs["group"],
        ChannelName=prereqs["channel"],
        OriginEndpointName=prereqs["endpoint"],
        HarvestJobName=good_job_name,
        HarvestedManifests={"HlsManifests": [{"ManifestName": "index"}]},
        ScheduleConfiguration={"StartTime": start, "EndTime": good_end},
        Destination={
            "S3Destination": {"BucketName": prereqs["bucket"], "DestinationPath": "good/"}
        },
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(
        lambda: _best_effort_cancel(
            mp, prereqs["group"], prereqs["channel"], prereqs["endpoint"], good_job_name
        )
    )
    assert created["Status"] == "QUEUED", f"expected QUEUED, got {created['Status']}"

    # independent read at the destination, not just the mutating call's own response.
    # Status is racy (real AWS observed moving QUEUED -> IN_PROGRESS within ~2s of
    # creation), so verify the accepted job's static schedule instead of pinning a
    # transient status value.
    got = mp.get_harvest_job(
        ChannelGroupName=prereqs["group"],
        ChannelName=prereqs["channel"],
        OriginEndpointName=prereqs["endpoint"],
        HarvestJobName=good_job_name,
    )
    assert got["ScheduleConfiguration"]["StartTime"].replace(microsecond=0) == start.replace(
        microsecond=0
    ), f"expected StartTime {start}, got {got['ScheduleConfiguration']['StartTime']}"
    assert got["ScheduleConfiguration"]["EndTime"].replace(microsecond=0) == good_end.replace(
        microsecond=0
    ), f"expected EndTime {good_end}, got {got['ScheduleConfiguration']['EndTime']}"
    good_names = {
        j["HarvestJobName"]
        for j in mp.list_harvest_jobs(
            ChannelGroupName=prereqs["group"],
            ChannelName=prereqs["channel"],
            OriginEndpointName=prereqs["endpoint"],
        )["Items"]
    }
    assert good_job_name in good_names, f"accepted job {good_job_name} missing from list"


def _create_harvest_prereqs(ctx) -> dict[str, str]:
    mp = ctx.client("mediapackagev2")
    s3 = ctx.client("s3")

    group = ctx.unique_name("sim2real-mpv2-cg-")
    mp.create_channel_group(ChannelGroupName=group, Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))

    channel = ctx.unique_name("sim2real-mpv2-ch-")
    mp.create_channel(
        ChannelGroupName=group, ChannelName=channel, Tags={"sim2real:managed": "true"}
    )
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=channel))

    endpoint = ctx.unique_name("sim2real-mpv2-oe-")
    endpoint_created = mp.create_origin_endpoint(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index", "ManifestWindowSeconds": 60}],
        Tags={"sim2real:managed": "true"},
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
    # us-east-1 is a literal S3 CreateBucket quirk (it rejects an explicit
    # LocationConstraint for its own region), not a pinned resource region.
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
