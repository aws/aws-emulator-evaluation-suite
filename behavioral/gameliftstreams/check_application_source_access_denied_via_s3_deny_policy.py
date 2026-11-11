"""application-source-access-denied-via-s3-deny-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "application-source-access-denied-via-s3-deny-policy"
GROUP = "overly-permissive"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApplication is rejected with AccessDeniedException and its message and creates no application
    when a bucket policy denies s3:GetObject on its source object, while a sibling object in the same bucket
    yields a READY application.
    """
    s3 = ctx.client("s3")
    gl = ctx.client("gameliftstreams")

    bucket = _create_bucket(ctx, s3)
    denied_prefix, denied_key = "build/", "build/start.sh"
    good_prefix, good_key = "good/", "good/start.sh"
    s3.put_object(Bucket=bucket, Key=denied_key, Body=b"#!/bin/sh\necho hi\n")
    s3.put_object(Bucket=bucket, Key=good_key, Body=b"#!/bin/sh\necho hi\n")

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyGetObject",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/{denied_key}",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(deny_policy))

    denied_desc = ctx.unique_name("sim2real-behav-gls-app-denied-")
    code, message = _error_code(
        lambda: gl.create_application(
            Description=denied_desc,
            RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
            ExecutablePath="start.sh",
            ApplicationSourceUri=f"s3://{bucket}/{denied_prefix}",
            Tags={"sim2real-env": "test"},
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}: {message}"
    expected = (
        "Access was denied for s3:ListBucket and s3:GetObject actions on the specified source URI"
    )
    assert _without_internal_id(message) == expected, f"expected {expected!r}, got {message!r}"

    # Effect absent: the synchronously-rejected request never allocated an application.
    items = gl.list_applications(MaxResults=100).get("Items", [])
    assert not any(i.get("Description") == denied_desc for i in items), (
        f"rejected application {denied_desc!r} unexpectedly appears in ListApplications"
    )

    # Positive control: an identical CreateApplication against another object in the same bucket, with no Deny
    # on it, reaches READY, so the rejection above comes from the object-scoped Deny.
    good_app = gl.create_application(
        Description=ctx.unique_name("sim2real-behav-gls-app-good-"),
        RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
        ExecutablePath="start.sh",
        ApplicationSourceUri=f"s3://{bucket}/{good_prefix}",
        Tags={"sim2real-env": "test"},
    )
    good_arn = good_app["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: gl.delete_application(Identifier=good_arn)))
    assert good_app["Status"] == "INITIALIZED", f"expected INITIALIZED, got {good_app['Status']}"

    good_final = _poll_until(
        lambda: gl.get_application(Identifier=good_arn),
        lambda r: r["Status"] not in ("INITIALIZED", "PROCESSING"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert good_final["Status"] == "READY", (
        f"positive control expected READY, got {good_final['Status']}: "
        f"{good_final.get('StatusReason')}"
    )


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


def _create_bucket(ctx, s3):
    bucket = ctx.unique_name("sim2real-behav-glsbkt-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    try:
        s3.create_bucket(**kwargs)  # us-east-1 rejects an explicit LocationConstraint
    except ClientError as e:
        raise AssertionError(
            f"S3 write access unavailable in this verification session ({e}); cannot "
            "provision real application content to exercise the deny-policy path"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
