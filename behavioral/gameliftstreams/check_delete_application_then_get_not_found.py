"""delete-application-then-get-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-application-then-get-not-found"
GROUP = "error-semantics"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteApplication, GetApplication on the deleted application fails with ResourceNotFoundException and
    its message, and DeleteApplication on an identifier never created fails with the same code and message.
    """
    gl = ctx.client("gameliftstreams")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-glsbkt-")
    try:
        # us-east-1 is S3's CreateBucket special case: passing a LocationConstraint there
        # is itself rejected, so the literal below is the API's own carve-out, not a pin.
        if ctx.region == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
        ctx.on_cleanup(lambda: _safe(lambda: s3.delete_bucket(Bucket=bucket)))
        s3.put_object(Bucket=bucket, Key="build/start.sh", Body=b"#!/bin/sh\necho hi\n")
        ctx.on_cleanup(lambda: _safe(lambda: s3.delete_object(Bucket=bucket, Key="build/start.sh")))
    except ClientError as e:
        raise AssertionError(
            f"S3 write access unavailable in this verification session ({e}); cannot "
            "provision a real application before proving the delete-then-get lifecycle"
        )

    app = gl.create_application(
        Description=ctx.unique_name("sim2real-behav-gls-app-"),
        RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
        ExecutablePath="start.sh",
        ApplicationSourceUri=f"s3://{bucket}/build",
    )
    app_arn = app["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: gl.delete_application(Identifier=app_arn)))

    # DeleteApplication rejects an application that hasn't finished processing (real AWS:
    # "not in READY or ERROR status"), so the positive control below needs a settled one.
    settled = _poll_until(
        lambda: gl.get_application(Identifier=app_arn),
        lambda a: a["Status"] in ("READY", "ERROR"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert settled["Status"] == "READY", f"application ended in {settled['Status']}: {settled.get('StatusReason')}"

    # Positive control: the delete succeeds on a real, existing application.
    gl.delete_application(Identifier=app_arn)

    def _probe():
        try:
            return gl.get_application(Identifier=app_arn)["Status"], ""
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message", "")

    code, message = _poll_until(
        _probe,
        lambda r: r[0] == "ResourceNotFoundException",
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Resource '{app_arn}' does not exist"
    assert _without_internal_id(message) == expected, f"expected {expected!r}, got {message!r}"

    # The delete-side lookup rejects a never-created identifier the same way, immediately.
    bogus_id = ctx.unique_name("a-")
    bogus_code, bogus_message = _error_code(lambda: gl.delete_application(Identifier=bogus_id))
    assert bogus_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {bogus_code!r}"
    bogus_arn = f"arn:aws:gameliftstreams:{ctx.region}:{ctx.account}:application/{bogus_id}"
    expected = f"Resource '{bogus_arn}' does not exist"
    assert _without_internal_id(bogus_message) == expected, f"expected {expected!r}, got {bogus_message!r}"


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


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchBucket",
            "NoSuchKey",
            "ResourceNotFoundException",
        ):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
