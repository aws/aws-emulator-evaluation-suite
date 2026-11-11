"""get-application-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-application-not-found"
GROUP = "error-semantics"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetApplication on a well-formed application identifier that was never created fails with
    ResourceNotFoundException and its message, while GetApplication on a real application returns its Arn.
    """
    gl = ctx.client("gameliftstreams")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-glsbkt-")
    try:
        if ctx.region == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
        ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
        s3.put_object(Bucket=bucket, Key="build/start.sh", Body=b"#!/bin/sh\necho hi\n")
        ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="build/start.sh"))
    except ClientError as e:
        raise AssertionError(
            f"S3 write access unavailable in this verification session ({e}); cannot "
            "provision real application content for the positive control"
        )

    real = gl.create_application(
        Description=ctx.unique_name("sim2real-behav-gls-app-"),
        RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
        ExecutablePath="start.sh",
        ApplicationSourceUri=f"s3://{bucket}/build",
    )
    real_arn = real["Arn"]
    ctx.on_cleanup(lambda: _delete_application_when_settled(gl, real_arn))

    # Positive control: GetApplication on the real, just-created application succeeds.
    fetched = gl.get_application(Identifier=real_arn)
    assert fetched["Arn"] == real_arn, f"expected {real_arn!r}, got {fetched['Arn']!r}"

    bogus_id = ctx.unique_name("a-")
    code, message = _error_code(lambda: gl.get_application(Identifier=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    bogus_arn = f"arn:aws:gameliftstreams:{ctx.region}:{ctx.account}:application/{bogus_id}"
    expected = f"Resource '{bogus_arn}' does not exist"
    assert _without_internal_id(message) == expected, f"expected {expected!r}, got {message!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
