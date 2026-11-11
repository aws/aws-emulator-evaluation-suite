"""create-application-source-access-denied-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-application-source-access-denied-rejected"
GROUP = "overly-permissive"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApplication is rejected with AccessDeniedException and its message and creates no application
    when a bucket policy denies reading the source; a readable bucket yields a READY application, and so does the
    call once the deny is removed.
    """
    s3 = ctx.client("s3")
    gls = ctx.client("gameliftstreams")

    good_bucket = _create_bucket(ctx, s3, suffix="good")
    s3.put_object(Bucket=good_bucket, Key="app/run.sh", Body=b"#!/bin/sh\nexit 0\n")

    denied_bucket = _create_bucket(ctx, s3, suffix="denied")
    s3.put_object(Bucket=denied_bucket, Key="app/run.sh", Body=b"#!/bin/sh\nexit 0\n")
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ExplicitDenyRead",
                "Effect": "Deny",
                "Principal": "*",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    f"arn:aws:s3:::{denied_bucket}",
                    f"arn:aws:s3:::{denied_bucket}/*",
                ],
            }
        ],
    }
    s3.put_bucket_policy(Bucket=denied_bucket, Policy=json.dumps(deny_policy))

    good_app = gls.create_application(
        Description=ctx.unique_name("sim2real-gls-app-good-"),
        RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
        ExecutablePath="run.sh",
        ApplicationSourceUri=f"s3://{good_bucket}/app/",
    )
    ctx.on_cleanup(lambda: _safe(lambda: gls.delete_application(Identifier=good_app["Id"])))

    denied_desc = ctx.unique_name("sim2real-gls-app-denied-")
    code, message = _error_code(
        lambda: gls.create_application(
            Description=denied_desc,
            RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
            ExecutablePath="run.sh",
            ApplicationSourceUri=f"s3://{denied_bucket}/app/",
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected = (
        "Access was denied for s3:ListBucket and s3:GetObject actions on the specified source URI"
    )
    assert _without_internal_id(message) == expected, f"expected {expected!r}, got {message!r}"

    # effect absent: the denied call never allocated an application
    items = gls.list_applications(MaxResults=100).get("Items", [])
    assert not any(i.get("Description") == denied_desc for i in items), (
        "a CreateApplication call rejected with AccessDeniedException must not have "
        "allocated an application"
    )

    # restore: removing the deny statement makes the identical call succeed, though S3 policy
    # removal takes a few seconds to propagate to the service's own access check, so retry
    # on a bounded window rather than assuming it is instant.
    s3.delete_bucket_policy(Bucket=denied_bucket)
    restored_app = _retry_until_success(
        lambda: gls.create_application(
            Description=denied_desc,
            RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
            ExecutablePath="run.sh",
            ApplicationSourceUri=f"s3://{denied_bucket}/app/",
        ),
        timeout_s=120.0,
        interval_s=5.0,
    )
    ctx.on_cleanup(lambda: _safe(lambda: gls.delete_application(Identifier=restored_app["Id"])))

    # positive control: the identical workflow against a readable bucket reaches READY
    good_final = _poll_until(
        lambda: gls.get_application(Identifier=good_app["Id"]),
        lambda a: a["Status"] in ("READY", "ERROR"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert good_final["Status"] == "READY", (
        f"positive control: expected READY for a source the bucket allows, got {good_final['Status']!r}"
    )

    restored_final = _poll_until(
        lambda: gls.get_application(Identifier=restored_app["Id"]),
        lambda a: a["Status"] in ("READY", "ERROR"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert restored_final["Status"] == "READY", (
        "identical call after removing the deny statement: expected READY, got "
        f"{restored_final['Status']!r}"
    )


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to raise a ClientError, it succeeded")


def _retry_until_success(fn, timeout_s=120.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_code = None
    while True:
        try:
            return fn()
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"identical call still rejected {timeout_s}s after removing the deny "
                    f"statement; last error {last_code!r}"
                )
            time.sleep(interval_s)


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
            # A Deny with Principal "*" also blocks the bucket owner, so clear any policy first: a deny left by a
            # failed run would otherwise block the ListBucket/GetObject calls below.
            s3.delete_bucket_policy(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
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
