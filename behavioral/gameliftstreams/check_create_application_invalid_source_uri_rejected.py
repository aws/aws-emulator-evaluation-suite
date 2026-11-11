"""create-application-invalid-source-uri-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-application-invalid-source-uri-rejected"
GROUP = "validation"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApplication rejects an ApplicationSourceUri that isn't a valid S3 URI with
    ValidationException, while an identical call against a real s3:// URI still succeeds
    (positive control) in the same run."""
    gls = ctx.client("gameliftstreams")
    s3 = ctx.client("s3")

    code, message = _error_code(
        lambda: gls.create_application(
            Description=ctx.unique_name("sim2real-gls-app-"),
            RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
            ExecutablePath="run.sh",
            ApplicationSourceUri="https://example.com/not-an-s3-uri.zip",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "'ApplicationSourceUri' must be a valid S3 URI starting with 's3://'"
    assert _without_internal_id(message) == expected, f"expected {expected!r}, got {message!r}"

    # positive control: an identical call against a real s3:// URI succeeds
    bucket = _create_bucket(ctx, s3, suffix="app")
    s3.put_object(Bucket=bucket, Key="app/run.sh", Body=b"#!/bin/sh\nexit 0\n")

    app = gls.create_application(
        Description=ctx.unique_name("sim2real-gls-app-"),
        RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
        ExecutablePath="run.sh",
        ApplicationSourceUri=f"s3://{bucket}/app/",
    )
    app_id = app["Id"]
    ctx.on_cleanup(lambda: _delete_application_when_settled(gls, app_id))
    assert app["Status"] in ("INITIALIZED", "PROCESSING"), (
        f"expected INITIALIZED or PROCESSING, got {app['Status']!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
