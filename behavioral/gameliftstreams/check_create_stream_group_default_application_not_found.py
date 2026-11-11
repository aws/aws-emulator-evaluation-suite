"""create-stream-group-default-application-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stream-group-default-application-not-found"
GROUP = "error-semantics"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStreamGroup rejects a DefaultApplicationIdentifier that does not exist with
    ResourceNotFoundException and allocates no stream group; the identical call succeeds
    (positive control) once DefaultApplicationIdentifier names a real, READY application."""
    gl = ctx.client("gameliftstreams")

    bad_desc = ctx.unique_name("sim2real-behav-gls-sg-bad-")
    bogus_app_id = ctx.unique_name("a-")
    code, message = _error_code(
        lambda: gl.create_stream_group(
            Description=bad_desc,
            StreamClass="gen4n_high",
            DefaultApplicationIdentifier=bogus_app_id,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    bogus_arn = f"arn:aws:gameliftstreams:{ctx.region}:{ctx.account}:application/{bogus_app_id}"
    expected = f"Resource '{bogus_arn}' does not exist"
    assert _without_internal_id(message) == expected, f"expected {expected!r}, got {message!r}"

    # Effect absent: no stream group carrying our distinctive description was created.
    items = gl.list_stream_groups(MaxResults=100).get("Items", [])
    assert not any(i.get("Description") == bad_desc for i in items), (
        f"a stream group with description {bad_desc!r} exists despite the rejected create"
    )

    # Positive control: the identical call succeeds once DefaultApplicationIdentifier names a
    # real, READY application.
    app_id = _create_ready_application(ctx, gl)

    good_desc = ctx.unique_name("sim2real-behav-gls-sg-good-")
    try:
        group = gl.create_stream_group(
            Description=good_desc,
            StreamClass="gen4n_high",
            DefaultApplicationIdentifier=app_id,
            Tags={"sim2real-check": CHECK},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServiceQuotaExceededException":
            raise AssertionError(
                f"account has no Gen4n GPU quota in this Region ({e}); GameLift Streams GPU "
                "quotas default to 0 and must be explicitly requested"
            )
        raise
    sg_arn = group["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: gl.delete_stream_group(Identifier=sg_arn)))
    assert group.get("DefaultApplication", {}).get("Id") == app_id, (
        f"expected DefaultApplication.Id == {app_id!r}, got {group.get('DefaultApplication')!r}"
    )

    # Independent read: the link stuck at the destination, not just in the create response.
    reread = gl.get_stream_group(Identifier=sg_arn)
    assert reread.get("DefaultApplication", {}).get("Id") == app_id, (
        f"expected DefaultApplication.Id == {app_id!r} on reread, got {reread.get('DefaultApplication')!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_ready_application(ctx, gl):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-gls-sg-app-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as e:
        raise AssertionError(
            f"S3 write access unavailable in this verification session ({e}); cannot "
            "provision the real application this positive control needs"
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )

    def _cleanup_bucket():
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup_bucket)
    s3.put_object(Bucket=bucket, Key="app/run.sh", Body=b"#!/bin/sh\nexit 0\n")

    app = gl.create_application(
        Description=ctx.unique_name("sim2real-behav-gls-sg-app-"),
        RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
        ExecutablePath="run.sh",
        ApplicationSourceUri=f"s3://{bucket}/app/",
        Tags={"sim2real-check": CHECK},
    )
    app_id = app["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: gl.delete_application(Identifier=app_id)))

    final = _poll_until(
        lambda: gl.get_application(Identifier=app_id),
        lambda a: a["Status"] in ("READY", "ERROR"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert final["Status"] == "READY", f"application ended in {final['Status']}: {final.get('StatusReason')}"
    return app_id


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


def _without_internal_id(message):
    """GameLift Streams ends every error message with a per-request "(Internal ID: <uuid>)"."""
    stable, sep, rest = message.rpartition(" (Internal ID: ")
    assert sep and rest.endswith(")"), f"expected a trailing '(Internal ID: ...)', got {message!r}"
    return stable


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
