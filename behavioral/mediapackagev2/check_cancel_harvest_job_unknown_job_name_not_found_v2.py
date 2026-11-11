"""cancel-harvest-job-unknown-job-name-not-found-v2."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "cancel-harvest-job-unknown-job-name-not-found-v2"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
    def _cleanup_bucket() -> None:
        # CreateHarvestJob writes an access-probe object under the destination path.
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)
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
            raise AssertionError(f"CreateHarvestJob rejected: ...{msg[-220:]}") from e
    raise AssertionError(
        f"CreateHarvestJob still failing on S3 destination after 90s of retries: "
        f"...{(last_exc.response['Error'].get('Message','') if last_exc else '')[-220:]}"
    )


def _create_and_cancel_job(ctx, mp, group, channel, endpoint, bucket, name_suffix):
    now = datetime.now(timezone.utc)
    job_name = ctx.unique_name(f"sim2real-mpkg-hj-{name_suffix}-")
    _create_harvest_job_with_retry(
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
        Destination={"S3Destination": {"BucketName": bucket, "DestinationPath": name_suffix}},
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
    assert status == "CANCELLED", f"setup job {job_name} never reached CANCELLED, saw {status}"
    return job_name


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelHarvestJob on a never-created HarvestJobName fails ResourceNotFoundException with the exact
    message and the name never appears in ListHarvestJobs; re-cancelling a CANCELLED job succeeds and
    leaves it CANCELLED, and a second cancelled job still reads CANCELLED at the end."""
    mp = ctx.client("mediapackagev2")
    group = ctx.unique_name("sim2real-mpkg-cg-")
    channel = ctx.unique_name("sim2real-mpkg-ch-")
    endpoint = ctx.unique_name("sim2real-mpkg-oe-")
    mp.create_channel_group(ChannelGroupName=group)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))
    mp.create_channel(ChannelGroupName=group, ChannelName=channel)
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=channel))
    endpoint_created = mp.create_origin_endpoint(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
        )
    )
    _grant_harvester_endpoint_access(ctx, mp, group, channel, endpoint, endpoint_created["Arn"])
    bucket = _create_harvest_bucket(ctx)

    # Positive control first: an ordinary cancel of a fresh job succeeds.
    control_job = _create_and_cancel_job(ctx, mp, group, channel, endpoint, bucket, "control")

    # A second cancelled job, re-cancelled further down.
    terminal_job = _create_and_cancel_job(ctx, mp, group, channel, endpoint, bucket, "terminal")

    # Negative case: cancel a HarvestJobName never created under this same parent chain.
    # Re-cancelling a CANCELLED job is an idempotent no-op, so it is not the refusal boundary.
    bogus_job_name = ctx.unique_name("sim2real-mpkg-hj-bogus-")
    err = _error(
        lambda: mp.cancel_harvest_job(
            ChannelGroupName=group,
            ChannelName=channel,
            OriginEndpointName=endpoint,
            HarvestJobName=bogus_job_name,
        )
    )
    assert err["Code"] == "ResourceNotFoundException", f"got {err!r}"
    expected_message = (
        "MediaPackage can't process your request because we can't find your harvest job. "
        "Verify your harvest job id or create a harvest job and then try again"
    )
    assert err["Message"] == expected_message, f"got {err!r}"

    # Effect absent: the never-created job never shows up in the listing.
    names_after_bogus_cancel = {
        j["HarvestJobName"]
        for j in mp.list_harvest_jobs(
            ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
        )["Items"]
    }
    assert bogus_job_name not in names_after_bogus_cancel, (
        f"bogus job {bogus_job_name!r} appeared in list_harvest_jobs after a "
        f"ResourceNotFoundException on cancel"
    )

    # Idempotency control: re-cancelling the already-CANCELLED terminal job is a safe
    # no-op — it does not error, and it does not disturb the job's terminal status.
    mp.cancel_harvest_job(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        HarvestJobName=terminal_job,
    )

    # Effect absent (no state change from the re-cancel).
    status_after = mp.get_harvest_job(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        HarvestJobName=terminal_job,
    )["Status"]
    assert status_after == "CANCELLED", f"terminal job {terminal_job} moved off CANCELLED to {status_after!r} after a re-cancel"

    status_control = mp.get_harvest_job(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        HarvestJobName=control_job,
    )["Status"]
    assert status_control == "CANCELLED", f"control job {control_job} was not CANCELLED at the end of the run, saw {status_control!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
