"""object-retention-compliance-cannot-shorten."""

from __future__ import annotations
import datetime
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "object-retention-compliance-cannot-shorten"
GROUP = 'object_lock'
SERVICES = ['s3']

#: The COMPLIANCE retention is the one thing here that cannot be undone on demand: no principal,
#: including the account root, may delete the version before this date. It is kept short (75 s)
#: so cleanup can bounded-poll the version delete until the retention lapses.
_RETAIN_S = 75
_TEARDOWN_BUDGET_S = 240.0
_TEARDOWN_POLL_S = 10.0


def _delete_lock_bucket(client, bucket):
    """Empty an Object-Lock bucket and delete it, bounded-polling out any surviving COMPLIANCE
    retention rather than swallowing the error and leaking the bucket."""
    deadline = time.monotonic() + _TEARDOWN_BUDGET_S
    while True:
        remaining = []
        try:
            for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
                for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                    key, vid = v["Key"], v["VersionId"]
                    if v not in page.get("DeleteMarkers", []):  # a delete marker holds no legal hold
                        try:
                            client.put_object_legal_hold(
                                Bucket=bucket, Key=key, VersionId=vid, LegalHold={"Status": "OFF"}
                            )
                        except ClientError as exc:
                            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                                raise
                    try:
                        client.delete_object(
                            Bucket=bucket, Key=key, VersionId=vid, BypassGovernanceRetention=True
                        )
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "AccessDenied":  # retention not yet lapsed
                            raise
                        remaining.append((key, vid))
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
            break
        if not remaining or time.monotonic() >= deadline:
            break
        time.sleep(_TEARDOWN_POLL_S)
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_lock_bucket(ctx, s3):
    """Create a bucket with Object Lock enabled at creation (implies versioning); lock-aware teardown."""
    name = ctx.unique_name("sim2real-behav-lockbkt-")
    params = {"Bucket": name, "ObjectLockEnabledForBucket": True}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_lock_bucket(s3, name))
    return name


def _client_error(fn) -> tuple[str, str]:
    """The botocore (Error.Code, Error.Message) of fn(); RAISES if fn succeeds, so a target that
    accepts what AWS refuses cannot pass that acceptance off as a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to fail and it succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Once a version is under COMPLIANCE retention, its RetainUntilDate can only be
    extended, never shortened - attempting to shorten it MUST fail."""
    s3 = ctx.client("s3")
    bucket = _new_lock_bucket(ctx, s3)
    key = "compliance.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"compliance-protected")

    now = datetime.datetime.now(datetime.timezone.utc)
    far_future = now + datetime.timedelta(seconds=_RETAIN_S)
    s3.put_object_retention(Bucket=bucket, Key=key, Retention={"Mode": "COMPLIANCE", "RetainUntilDate": far_future})

    sooner = now + datetime.timedelta(seconds=20)

    def _shorten():
        return s3.put_object_retention(
            Bucket=bucket, Key=key, Retention={"Mode": "COMPLIANCE", "RetainUntilDate": sooner}
        )

    code, message = _client_error(_shorten)
    assert code == "AccessDenied", f"expected AccessDenied shortening a COMPLIANCE RetainUntilDate, got {code}"
    assert message == "Access Denied because object protected by object lock.", f"unexpected message {message!r}"

    fetched = s3.get_object_retention(Bucket=bucket, Key=key)["Retention"]
    assert fetched["Mode"] == "COMPLIANCE", (
        f"expected retention Mode to remain COMPLIANCE after the rejected shorten, got {fetched['Mode']!r}"
    )
    # Retention date must remain at (or beyond) the originally-set far-future date.
    assert fetched["RetainUntilDate"] >= far_future - datetime.timedelta(seconds=5), (
        f"expected RetainUntilDate >= {far_future!r} (the rejected shorten must not have taken "
        f"effect), got {fetched['RetainUntilDate']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
