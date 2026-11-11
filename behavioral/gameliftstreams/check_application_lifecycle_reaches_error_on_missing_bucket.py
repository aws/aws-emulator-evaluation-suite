"""application-lifecycle-reaches-error-on-missing-bucket."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "application-lifecycle-reaches-error-on-missing-bucket"
GROUP = "overly-permissive"
SERVICES = ["gameliftstreams"]

_RUNTIME = {"Type": "UBUNTU", "Version": "22_04_LTS"}
_KEY = "build/start.sh"
_BODY = b"#!/bin/sh\necho hi\n"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApplication with an ApplicationSourceUri in a bucket that does not exist is rejected at once with
    ValidationException and its message and creates no application; the same call succeeds after the bucket
    is created.
    """
    gl = ctx.client("gameliftstreams")
    s3 = ctx.client("s3")

    # --- Positive control: a real S3 object resolves and the call succeeds.
    ctrl_bucket = _create_bucket(ctx, s3)
    ctrl = gl.create_application(
        Description=ctx.unique_name("sim2real-behav-gls-ctrl-"),
        RuntimeEnvironment=_RUNTIME,
        ExecutablePath="start.sh",
        ApplicationSourceUri=f"s3://{ctrl_bucket}/build",
    )
    ctrl_arn = ctrl["Arn"]
    ctx.on_cleanup(lambda: _delete_application_when_settled(gl, ctrl_arn))
    assert ctrl["Status"] in ("INITIALIZED", "PROCESSING"), (
        f"positive control: CreateApplication with a real S3 object must succeed, "
        f"got status {ctrl['Status']!r}"
    )

    # --- Break exactly one thing: the target bucket does not exist yet.
    test_bucket = ctx.unique_name("sim2real-behav-glsbkt-")
    test_desc = ctx.unique_name("sim2real-behav-gls-noexist-")
    source_uri = f"s3://{test_bucket}/build"

    code, message = _error_code(
        lambda: gl.create_application(
            Description=test_desc,
            RuntimeEnvironment=_RUNTIME,
            ExecutablePath="start.sh",
            ApplicationSourceUri=source_uri,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "No S3 objects were found at the specified source URI"
    assert _without_internal_id(message) == expected, f"expected {expected!r}, got {message!r}"

    # Effect absent: the rejected request never allocated an application resource.
    items = gl.list_applications(MaxResults=100).get("Items", [])
    assert not any(i.get("Description") == test_desc for i in items), (
        "CreateApplication rejected for a missing bucket must not leave an application behind"
    )

    # Restore: create the bucket the URI pointed at, then retry the identical call. The object-existence check
    # takes a moment to see the new bucket and object, so this retries that specific error to a bounded deadline.
    _create_bucket(ctx, s3, bucket=test_bucket)
    restored = _retry_on_missing_object(
        lambda: gl.create_application(
            Description=test_desc,
            RuntimeEnvironment=_RUNTIME,
            ExecutablePath="start.sh",
            ApplicationSourceUri=source_uri,
        )
    )
    restored_arn = restored["Arn"]
    ctx.on_cleanup(lambda: _delete_application_when_settled(gl, restored_arn))
    assert restored["Status"] in ("INITIALIZED", "PROCESSING"), (
        f"the identical call must succeed once the bucket exists, got status {restored['Status']!r}"
    )

    # Terminal read: independent of the mutating CreateApplication response. GameLift Streams
    # normalizes a prefix-style ApplicationSourceUri by appending a trailing slash.
    fetched = gl.get_application(Identifier=restored_arn)
    assert fetched["ApplicationSourceUri"] == source_uri + "/", (
        f"GetApplication must reflect the same (normalized) source uri, "
        f"got {fetched.get('ApplicationSourceUri')!r}"
    )
    assert fetched["Status"] in ("INITIALIZED", "PROCESSING"), (
        f"GetApplication must independently confirm the restored application is live, "
        f"got status {fetched['Status']!r}"
    )


def _create_bucket(ctx, s3, bucket=None):
    bucket = bucket or ctx.unique_name("sim2real-behav-glsbkt-")
    try:
        if ctx.region == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
        ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
        s3.put_object(Bucket=bucket, Key=_KEY, Body=_BODY)
        ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=_KEY))
    except ClientError as e:
        raise AssertionError(
            f"S3 write access unavailable in this verification session ({e}); cannot "
            "provision real application content"
        )
    return bucket


def _retry_on_missing_object(fn, *, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            error = e.response.get("Error", {})
            if error.get("Code") == "ValidationException" and "No S3 objects" in error.get("Message", ""):
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(
        f"CreateApplication kept reporting no S3 objects for {timeout_s}s after the bucket and "
        f"object were created; last error: {last_err}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected CreateApplication to be rejected, but it SUCCEEDED and returned {result!r}")


def _without_internal_id(message):
    """GameLift Streams ends every error message with a per-request "(Internal ID: <uuid>)"."""
    stable, sep, rest = message.rpartition(" (Internal ID: ")
    assert sep and rest.endswith(")"), f"expected a trailing '(Internal ID: ...)', got {message!r}"
    return stable


def _delete_application_when_settled(gl, arn, timeout_s=300.0):
    """DeleteApplication refuses an application that is still INITIALIZED or PROCESSING."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            gl.delete_application(Identifier=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ValidationException" or time.monotonic() >= deadline:
                raise
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
