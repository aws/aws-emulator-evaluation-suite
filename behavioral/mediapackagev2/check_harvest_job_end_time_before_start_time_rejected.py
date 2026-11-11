"""harvest-job-end-time-before-start-time-rejected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "harvest-job-end-time-before-start-time-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]

END_BEFORE_START = (
    "Validation error encountered at request.scheduleConfiguration: Harvest job end time must "
    "be later than the start time. Check your configured start and end times and then try again"
)
HARVEST_JOB_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your harvest job. "
    "Verify your harvest job id or create a harvest job and then try again"
)


def _client_error(fn):
    """Call fn(); return its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e
    raise AssertionError(f"expected rejection but call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateHarvestJob with EndTime earlier than StartTime is rejected with ValidationException."""
    mp = ctx.client("mediapackagev2")
    s3 = ctx.client("s3")

    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    endpoint_name = ctx.unique_name("sim2real-mpv2-oe-")
    bad_job_name = ctx.unique_name("sim2real-mpv2-hj-bad-")
    good_job_name = ctx.unique_name("sim2real-mpv2-hj-good-")
    bucket_name = ctx.unique_name("sim2real-mpv2-harvest-")

    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    mp.create_channel(
        ChannelGroupName=group_name, ChannelName=channel_name, Tags={"sim2real": "true"}
    )
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))
    endpoint_created = mp.create_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        Tags={"sim2real": "true"},
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
    err = _client_error(
        lambda: mp.create_harvest_job(
            ChannelGroupName=group_name,
            ChannelName=channel_name,
            OriginEndpointName=endpoint_name,
            HarvestJobName=bad_job_name,
            HarvestedManifests={"HlsManifests": [{"ManifestName": "index"}]},
            ScheduleConfiguration={
                "StartTime": now + timedelta(minutes=15),
                "EndTime": now + timedelta(minutes=10),
            },
            Destination={"S3Destination": {"BucketName": bucket_name, "DestinationPath": "harvested"}},
        )
    )
    code = err.response["Error"]["Code"]
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    message = err.response["Error"]["Message"]
    assert message == END_BEFORE_START, f"expected message {END_BEFORE_START!r}, got {message!r}"
    validation_type = err.response.get("ValidationExceptionType")
    assert validation_type == "END_TIME_EARLIER_THAN_START_TIME", (
        f"expected ValidationExceptionType END_TIME_EARLIER_THAN_START_TIME, got {validation_type!r}"
    )

    # Effect absent: no harvest job with that name was created.
    not_found_err = _client_error(
        lambda: mp.get_harvest_job(
            ChannelGroupName=group_name,
            ChannelName=channel_name,
            OriginEndpointName=endpoint_name,
            HarvestJobName=bad_job_name,
        )
    )
    not_found_code = not_found_err.response["Error"]["Code"]
    assert not_found_code == "ResourceNotFoundException", (
        f"rejected job {bad_job_name} should not exist, got {not_found_code!r}"
    )
    not_found_message = not_found_err.response["Error"]["Message"]
    assert not_found_message == HARVEST_JOB_NOT_FOUND, f"expected message {HARVEST_JOB_NOT_FOUND!r}, got {not_found_message!r}"

    # Positive control: a valid StartTime < EndTime schedule succeeds.
    good = mp.create_harvest_job(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        HarvestJobName=good_job_name,
        HarvestedManifests={"HlsManifests": [{"ManifestName": "index"}]},
        ScheduleConfiguration={
            "StartTime": now + timedelta(minutes=10),
            "EndTime": now + timedelta(minutes=15),
        },
        Destination={"S3Destination": {"BucketName": bucket_name, "DestinationPath": "harvested"}},
        Tags={"sim2real": "true"},
    )
    assert good["Status"] == "QUEUED", f"expected valid schedule to be QUEUED, got {good['Status']!r}"
    ctx.on_cleanup(
        lambda: mp.cancel_harvest_job(
            ChannelGroupName=group_name,
            ChannelName=channel_name,
            OriginEndpointName=endpoint_name,
            HarvestJobName=good_job_name,
        )
    )


def _create_bucket(ctx, s3, bucket_name: str) -> None:
    kwargs = {"Bucket": bucket_name}
    # us-east-1 is S3's implicit default: CreateBucket rejects an explicit
    # LocationConstraint of "us-east-1", so the constraint is only passed for every other region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
