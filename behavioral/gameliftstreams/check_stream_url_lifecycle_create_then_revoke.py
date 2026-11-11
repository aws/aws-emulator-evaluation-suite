"""stream-url-lifecycle-create-then-revoke."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stream-url-lifecycle-create-then-revoke"
GROUP = "state"
SERVICES = ["gameliftstreams"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStreamUrl produces a stream URL in ACTIVE status; RevokeStreamUrl (REVOKE_URL
    mode) transitions it one-way to REVOKED with StatusReason userRevoked, and GetStreamUrl
    reflects the new status."""
    gl = ctx.client("gameliftstreams")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-glsbkt-")
    key = "build/start.sh"
    try:
        if ctx.region == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
        ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
        s3.put_object(Bucket=bucket, Key=key, Body=b"#!/bin/sh\necho hi\n")
        ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
        s3.put_bucket_policy(
            Bucket=bucket,
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowGameLiftStreamsRead",
                            "Effect": "Allow",
                            "Principal": {"Service": "gameliftstreams.amazonaws.com"},
                            "Action": ["s3:GetObject", "s3:ListBucket"],
                            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                        }
                    ],
                }
            ),
        )
    except ClientError as e:
        raise AssertionError(
            f"S3 write access unavailable in this verification session ({e}); cannot "
            "provision a real READY application before spending GPU quota"
        )

    app = gl.create_application(
        Description=ctx.unique_name("sim2real-behav-gls-app-"),
        RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
        ExecutablePath="start.sh",
        ApplicationSourceUri=f"s3://{bucket}/build",
        Tags={"sim2real-env": "test"},
    )
    app_arn = app["Arn"]
    ctx.on_cleanup(lambda: gl.delete_application(Identifier=app_arn))
    ready = _poll_until(
        lambda: gl.get_application(Identifier=app_arn),
        lambda r: r["Status"] not in ("INITIALIZED", "PROCESSING"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert ready["Status"] == "READY", f"application never reached READY: {ready['Status']} ({ready.get('StatusReason')})"

    sg = gl.create_stream_group(
        Description=ctx.unique_name("sim2real-behav-gls-sg-"),
        StreamClass="gen6n_small",
        LocationConfigurations=[{"LocationName": ctx.region, "MaximumCapacity": 12}],
        Tags={"sim2real-env": "test"},
    )
    sg_arn = sg["Arn"]
    ctx.on_cleanup(lambda: gl.delete_stream_group(Identifier=sg_arn))
    activated = _poll_until(
        lambda: gl.get_stream_group(Identifier=sg_arn),
        lambda r: r["Status"] not in ("ACTIVATING", "UPDATING_LOCATIONS"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert activated["Status"] == "ACTIVE", (
        f"stream group never reached ACTIVE: {activated['Status']} ({activated.get('StatusReason')})"
    )
    gl.associate_applications(Identifier=sg_arn, ApplicationIdentifiers=[app_arn])
    _poll_until(
        lambda: gl.get_application(Identifier=app_arn),
        lambda r: any(
            rs["Location"] == ctx.region and rs["Status"] == "COMPLETED"
            for rs in r.get("ReplicationStatuses", [])
        ),
        timeout_s=300.0,
        interval_s=10.0,
    )

    created = gl.create_stream_url(
        Identifier=sg_arn,
        ApplicationIdentifier=app_arn,
        Protocol="WebRTC",
        UrlExpiresAfterMinutes=60,
        Locations=[ctx.region],
    )
    url_id = created["StreamUrlId"]
    assert created["Status"] == "ACTIVE", f"expected ACTIVE on create, got {created['Status']}"
    ctx.on_cleanup(lambda: gl.revoke_stream_url(Identifier=sg_arn, StreamUrlIdentifier=url_id))

    gl.revoke_stream_url(
        Identifier=sg_arn, StreamUrlIdentifier=url_id, RevocationMode="REVOKE_URL"
    )
    fetched = gl.get_stream_url(Identifier=sg_arn, StreamUrlIdentifier=url_id)
    assert fetched["Status"] == "REVOKED", f"expected REVOKED, got {fetched['Status']}"
    assert fetched["StatusReason"] == "userRevoked", (
        f"expected StatusReason userRevoked, got {fetched.get('StatusReason')}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
