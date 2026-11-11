"""list-harvest-jobs-status-filter."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "list-harvest-jobs-status-filter"
GROUP = "state"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListHarvestJobs' Status filter returns a cancelled job under CANCELLED only, and a second
    job under the status it holds across the List call, without the cancelled one."""
    mp = ctx.client("mediapackagev2")
    s3 = ctx.client("s3")

    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    endpoint_name = ctx.unique_name("sim2real-mpv2-oe-")
    cancelled_job_name = ctx.unique_name("sim2real-mpv2-hj-cxl-")
    queued_job_name = ctx.unique_name("sim2real-mpv2-hj-q-")
    bucket_name = ctx.unique_name("sim2real-mpv2-harvest-")

    mp.create_channel_group(ChannelGroupName=group_name)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))
    endpoint_created = mp.create_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
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
    schedule = {"StartTime": now - timedelta(minutes=10), "EndTime": now - timedelta(minutes=5)}
    destination = {"S3Destination": {"BucketName": bucket_name, "DestinationPath": "harvested"}}
    manifests = {"HlsManifests": [{"ManifestName": "index"}]}

    mp.create_harvest_job(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        HarvestJobName=cancelled_job_name,
        HarvestedManifests=manifests,
        ScheduleConfiguration=schedule,
        Destination=destination,
    )
    mp.cancel_harvest_job(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        HarvestJobName=cancelled_job_name,
    )

    mp.create_harvest_job(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        HarvestJobName=queued_job_name,
        HarvestedManifests=manifests,
        ScheduleConfiguration=schedule,
        Destination=destination,
    )
    ctx.on_cleanup(
        lambda: mp.cancel_harvest_job(
            ChannelGroupName=group_name,
            ChannelName=channel_name,
            OriginEndpointName=endpoint_name,
            HarvestJobName=queued_job_name,
        )
    )

    cancelled_page = mp.list_harvest_jobs(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name, Status="CANCELLED"
    )
    cancelled_names = {item["HarvestJobName"] for item in cancelled_page["Items"]}
    assert cancelled_job_name in cancelled_names, (
        f"expected {cancelled_job_name} in the CANCELLED filter, got {cancelled_names}"
    )
    assert queued_job_name not in cancelled_names, (
        f"{queued_job_name} leaked into the CANCELLED filter: {cancelled_names}"
    )

    # The second job moves through QUEUED/IN_PROGRESS to a terminal status on its own and AWS
    # documents no dwell time, so the filter is graded on a status that the job holds both
    # before and after the List call (bounded re-read until one is held).
    def _queued_status():
        return mp.get_harvest_job(
            ChannelGroupName=group_name,
            ChannelName=channel_name,
            OriginEndpointName=endpoint_name,
            HarvestJobName=queued_job_name,
        )["Status"]

    timeout_s = 120.0
    budget_s = _budget_s(ctx, timeout_s)
    start = time.monotonic()
    stop = start + min(timeout_s, budget_s)
    observed = []
    while True:
        queued_page_status = _queued_status()
        assert queued_page_status in ("QUEUED", "IN_PROGRESS", "COMPLETED", "FAILED"), queued_page_status
        active_page = mp.list_harvest_jobs(
            ChannelGroupName=group_name,
            ChannelName=channel_name,
            OriginEndpointName=endpoint_name,
            Status=queued_page_status,
        )
        status_after = _queued_status()
        observed.append((queued_page_status, status_after))
        if status_after == queued_page_status:
            break
        if time.monotonic() >= stop and budget_s < timeout_s:
            raise TimeoutError(
                f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                f"{timeout_s}s status wait ended ({observed}); not graded"
            )
        assert time.monotonic() < stop, (
            f"{queued_job_name} never held one status across a ListHarvestJobs call: {observed}"
        )
        time.sleep(2)
    active_names = {item["HarvestJobName"] for item in active_page["Items"]}
    assert queued_job_name in active_names, (
        f"expected {queued_job_name} (Status={queued_page_status}) in the "
        f"{queued_page_status} filter, got {active_names}"
    )
    assert cancelled_job_name not in active_names, (
        f"{cancelled_job_name} leaked into the {queued_page_status} filter: {active_names}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _create_bucket(ctx, s3, bucket_name: str) -> None:
    kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
