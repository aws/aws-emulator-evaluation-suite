"""bucket-policy-deny-enforcement."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "bucket-policy-deny-enforcement"
GROUP = 'auth_enforcement'
SERVICES = ['s3']

def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; raises unless gone."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until_refused(fn, timeout_s=60.0, interval_s=2.0):
    """Call fn() until it raises ClientError; return that error's (Code, Message). A call that
    keeps succeeding past the deadline raises AssertionError."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"call kept succeeding for {timeout_s}s; last result {result!r}")
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An explicit Deny bucket policy (Principal "*") makes GetObject and PutObject fail with
    AccessDenied and the exact explicit-deny messages, even for the owner; the denied PutObject leaves
    the body unchanged, and both calls work again once the Deny is removed."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "deny-me.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"secret-data")

    # positive control: the object is readable before any Deny exists
    precontrol = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert precontrol == b"secret-data", f"expected object readable before any Deny, got {precontrol!r}"

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyAllGetPut",
                "Effect": "Deny",
                "Principal": "*",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]

    def _explicit_deny(action):
        return (
            f"User: {caller_arn} is not authorized to perform: {action} on resource: "
            f'"arn:aws:s3:::{bucket}/{key}" with an explicit deny in a resource-based policy'
        )

    try:
        # a fresh bucket policy reaches every S3 front end eventually, not at once; poll the
        # read (it has no side effect) until the Deny is in force, bounded, raising on timeout
        code, message = _poll_until_refused(lambda: s3.get_object(Bucket=bucket, Key=key))
        assert code == "AccessDenied", f"expected AccessDenied for GetObject under explicit Deny, got {code}"
        assert message == _explicit_deny("s3:GetObject"), message

        code2, message2 = _error(lambda: s3.put_object(Bucket=bucket, Key=key, Body=b"overwrite"))
        assert code2 == "AccessDenied", f"expected AccessDenied for PutObject under explicit Deny, got {code2}"
        assert message2 == _explicit_deny("s3:PutObject"), message2
    finally:
        # remove the self-blocking policy so teardown's own delete path isn't put at risk
        s3.delete_bucket_policy(Bucket=bucket)

    # the denied PutObject must have had no side effect -- the deny blocked the mutation
    # itself, not just returned an error while still committing the write underneath it
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert body == b"secret-data", f"expected object unchanged by denied PutObject, got {body!r}"

    # restore is real: with the Deny gone, the identical calls that were just rejected succeed
    s3.put_object(Bucket=bucket, Key=key, Body=b"overwrite-after-restore")
    restored = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert restored == b"overwrite-after-restore", f"expected write to succeed after Deny removed, got {restored!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
