"""create-application-content-lifecycle-ready."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-application-content-lifecycle-ready"
GROUP = "lifecycle"
SERVICES = ["gameliftstreams"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApplication against REAL S3 content actually copies/validates the content end to
    end and transitions the application from INITIALIZED through PROCESSING to READY."""
    s3 = ctx.client("s3")
    gls = ctx.client("gameliftstreams")

    bucket = _create_bucket(ctx, s3, suffix="app")
    s3.put_object(Bucket=bucket, Key="app/run.sh", Body=b"#!/bin/sh\nexit 0\n")

    app = gls.create_application(
        Description=ctx.unique_name("sim2real-gls-app-"),
        RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
        ExecutablePath="run.sh",
        ApplicationSourceUri=f"s3://{bucket}/app/",
        Tags={"sim2real-audit": "true"},
    )
    app_id = app["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: gls.delete_application(Identifier=app_id)))
    assert app["Status"] == "INITIALIZED", f"expected INITIALIZED immediately after CreateApplication, got {app['Status']!r}"

    final = _poll_until(
        lambda: gls.get_application(Identifier=app_id),
        lambda a: a["Status"] in ("READY", "ERROR"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert final["Status"] == "READY", f"application ended in {final['Status']}: {final.get('StatusReason')}"
    assert final["ExecutablePath"] == "run.sh", f"expected ExecutablePath 'run.sh', got {final['ExecutablePath']!r}"
    assert final["RuntimeEnvironment"]["Type"] == "UBUNTU", f"expected RuntimeEnvironment.Type 'UBUNTU', got {final['RuntimeEnvironment']['Type']!r}"

    replication = final.get("ReplicationStatuses") or []
    assert replication, "expected ReplicationStatuses to report at least one location once READY, got none"
    assert all(r["Status"] == "COMPLETED" for r in replication), (
        f"expected every location's content replication to be COMPLETED once the application "
        f"reports READY (content is not usable for streaming from a location still REPLICATING), "
        f"got {replication!r}"
    )


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
        s3.put_bucket_tagging(
            Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-audit", "Value": "true"}]}
        )
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
