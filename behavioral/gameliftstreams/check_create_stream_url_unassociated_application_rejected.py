"""create-stream-url-unassociated-application-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-stream-url-unassociated-application-rejected"
GROUP = "overly-permissive"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStreamUrl for an application not associated with the stream group fails with ValidationException
    naming both and creates no stream URL; after AssociateApplications the same call returns an ACTIVE URL.
    """
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    s3 = ctx.client("s3")
    gls = ctx.client("gameliftstreams")

    app = _create_ready_application(ctx, gls, s3, teardown_deadline)
    group = _create_active_stream_group(
        ctx, gls, teardown_deadline, location_configurations=[{"LocationName": ctx.region, "MaximumCapacity": 2}]
    )
    _wait_location_active(ctx, gls, group["Arn"])

    err = _client_error(
        lambda: gls.create_stream_url(
            Identifier=group["Arn"],
            ApplicationIdentifier=app["Id"],
            Protocol="WebRTC",
            UrlExpiresAfterMinutes=15,
            Locations=[ctx.region],
        )
    )
    assert err.get("Code") == "ValidationException", (
        f"expected ValidationException for a CreateStreamUrl against an unassociated "
        f"application, got {err!r}"
    )
    expected = f"Application '{app['Arn']}' is not associated with stream group '{group['Arn']}'"
    message = err.get("Message", "")
    assert _without_internal_id(message) == expected, f"expected {expected!r}, got {message!r}"

    # effect absent: no stream URL exists for this stream group
    listing = gls.list_stream_urls(StreamGroupIdentifier=group["Arn"]).get("Items", [])
    assert listing == [], f"expected no stream URLs after the rejected CreateStreamUrl, got {listing!r}"

    # positive control: associating first makes the identical call succeed
    gls.associate_applications(Identifier=group["Arn"], ApplicationIdentifiers=[app["Id"]])
    ctx.on_cleanup(lambda: _disassociate_if_present(gls, group["Arn"], app["Arn"]))
    url = gls.create_stream_url(
        Identifier=group["Arn"],
        ApplicationIdentifier=app["Id"],
        Protocol="WebRTC",
        UrlExpiresAfterMinutes=15,
        Locations=[ctx.region],
    )
    assert url["Status"] == "ACTIVE", f"expected ACTIVE from CreateStreamUrl, got {url['Status']!r}"

    # terminal read: independent of the mutating CreateStreamUrl call
    fetched = gls.get_stream_url(Identifier=group["Arn"], StreamUrlIdentifier=url["StreamUrlId"])
    assert fetched["Status"] == "ACTIVE", (
        f"expected GetStreamUrl to reflect ACTIVE after association, got {fetched['Status']!r}"
    )


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected real AWS to reject this call, but it SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)


def _create_bucket(ctx, s3, suffix="app"):
    from botocore.exceptions import ClientError


    bucket = ctx.unique_name(f"sim2real-behav-gls-{suffix}-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as e:
        raise AssertionError(
            f"S3 write access unavailable in this verification session ({e}); cannot "
            "provision real application content"
        )

    def _cleanup():
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_ready_application(ctx, gls, s3, teardown_deadline, script_body=b"#!/bin/sh\nexit 0\n", timeout_s=600.0):
    bucket = _create_bucket(ctx, s3, suffix="app")
    s3.put_object(Bucket=bucket, Key="app/run.sh", Body=script_body)
    app = gls.create_application(
        Description=ctx.unique_name("sim2real-gls-app-"),
        RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
        ExecutablePath="run.sh",
        ApplicationSourceUri=f"s3://{bucket}/app/",
    )
    app_id = app["Id"]
    ctx.on_cleanup(lambda: _delete_application_when_settled(gls, app_id, teardown_deadline))
    final = _poll_until(
        lambda: gls.get_application(Identifier=app_id),
        lambda a: a["Status"] in ("READY", "ERROR"),
        timeout_s=timeout_s,
        interval_s=10.0,
    )
    if final["Status"] != "READY":
        raise AssertionError(f"application did not reach READY: {final.get('StatusReason')}")
    return final


def _create_active_stream_group(ctx, gls, teardown_deadline, location_configurations=None, timeout_s=900.0):
    kwargs = {"Description": ctx.unique_name("sim2real-gls-sg-"), "StreamClass": "gen4n_high"}
    if location_configurations:
        kwargs["LocationConfigurations"] = location_configurations
    group = gls.create_stream_group(**kwargs)
    arn = group["Arn"]
    ctx.on_cleanup(lambda: _delete_stream_group_when_settled(gls, arn, teardown_deadline))
    final = _poll_until(
        lambda: gls.get_stream_group(Identifier=arn),
        lambda g: g["Status"] in ("ACTIVE", "ACTIVE_WITH_ERRORS", "ERROR"),
        timeout_s=timeout_s,
        interval_s=10.0,
    )
    if final["Status"] != "ACTIVE":
        raise AssertionError(
            f"stream group did not reach ACTIVE: {final['Status']}/{final.get('StatusReason')}"
        )
    return final


def _wait_location_active(ctx, gls, arn, timeout_s=600.0):
    def _location_is_active(group):
        for loc in group["LocationStates"]:
            if loc["LocationName"] == ctx.region:
                return loc["Status"] == "ACTIVE"
        return False

    return _poll_until(
        lambda: gls.get_stream_group(Identifier=arn),
        _location_is_active,
        timeout_s=timeout_s,
        interval_s=15.0,
    )


def _without_internal_id(message):
    """GameLift Streams ends every error message with a per-request "(Internal ID: <uuid>)"."""
    stable, sep, rest = message.rpartition(" (Internal ID: ")
    assert sep and rest.endswith(")"), f"expected a trailing '(Internal ID: ...)', got {message!r}"
    return stable


# The suite's 900 s teardown budget: one deadline shared by every teardown of a run.
_TEARDOWN_S = 900.0


def _teardown_deadline(teardown_deadline):
    return teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_S - 120.0)


def _delete_stream_group_when_settled(gls, arn, teardown_deadline, interval_s=2.0):
    """DeleteStreamGroup refuses a group that is still ACTIVATING, so retry until it is
    accepted, then wait until the group is gone, to the shared teardown deadline."""
    from botocore.exceptions import ClientError

    deadline = _teardown_deadline(teardown_deadline)
    while True:
        try:
            gls.delete_stream_group(Identifier=arn)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ValidationException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)
    while True:
        try:
            gls.get_stream_group(Identifier=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"stream group {arn} still present at the teardown deadline")
        time.sleep(interval_s)

def _delete_application_when_settled(gls, arn, teardown_deadline, interval_s=2.0):
    """DeleteApplication refuses an application that is still processing or still associated
    with a stream group that is being deleted, so retry until it is accepted or already gone."""
    from botocore.exceptions import ClientError

    deadline = _teardown_deadline(teardown_deadline)
    while True:
        try:
            gls.delete_application(Identifier=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ValidationException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)

def _disassociate_if_present(gls, sg_arn, app_arn):
    from botocore.exceptions import ClientError

    try:
        gls.disassociate_applications(Identifier=sg_arn, ApplicationIdentifiers=[app_arn])
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
