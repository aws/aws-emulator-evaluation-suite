"""object-retention-until-date-enforces-window."""
from __future__ import annotations

import datetime as dt
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-retention-until-date-enforces-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["s3"]


# timing:real-time — retention: 12 s https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """Within RetainUntilDate, deleting the protected version is AccessDenied and GetObjectRetention
    echoes the exact date; after expiry the date still reads back and the same delete succeeds,
    leaving the version gone (NoSuchVersion)."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx, ObjectLockEnabledForBucket=True)
    key = "retained.txt"
    put_resp = s3.put_object(Bucket=bucket, Key=key, Body=b"protected payload")
    version_id = put_resp["VersionId"]

    retain_until = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=12)
    s3.put_object_retention(
        Bucket=bucket, Key=key, VersionId=version_id,
        Retention={"Mode": "GOVERNANCE", "RetainUntilDate": retain_until},
    )

    # GetObjectRetention reflects exactly the RetainUntilDate we just set (to the second).
    got = s3.get_object_retention(Bucket=bucket, Key=key, VersionId=version_id)["Retention"]
    assert got["Mode"] == "GOVERNANCE", f"expected GOVERNANCE mode, got {got['Mode']!r}"
    delta = abs((got["RetainUntilDate"] - retain_until).total_seconds())
    assert delta < 1.0, f"RetainUntilDate drifted by {delta}s from what was set"

    # While inside the retention window, deleting this exact version is rejected.
    denied_code, denied_message = _client_error(
        lambda: s3.delete_object(Bucket=bucket, Key=key, VersionId=version_id)
    )
    assert denied_code == "AccessDenied", f"expected AccessDenied while retention active, got {denied_code!r}"
    assert denied_message == "Access Denied because object protected by object lock.", (
        f"unexpected message {denied_message!r}"
    )
    # ... and the version must still be physically present (the denial had no side effect).
    still_present = s3.list_object_versions(Bucket=bucket, Prefix=key)["Versions"]
    assert any(v["VersionId"] == version_id for v in still_present), (
        f"version {version_id} missing from list_object_versions after a denied delete"
    )

    # Wait out the window, then confirm the SAME deletion that was denied now succeeds.
    deadline = time.monotonic() + 30
    while dt.datetime.now(dt.timezone.utc) < retain_until and time.monotonic() < deadline:
        time.sleep(1)
    assert dt.datetime.now(dt.timezone.utc) >= retain_until, "retention window never elapsed within bound"

    # GetObjectRetention still reports the (now-expired) RetainUntilDate -- it isn't cleared
    # just because the clock passed it.
    post_expiry = s3.get_object_retention(Bucket=bucket, Key=key, VersionId=version_id)["Retention"]
    post_delta = abs((post_expiry["RetainUntilDate"] - retain_until).total_seconds())
    assert post_delta < 1.0, (
        f"expired RetainUntilDate should still read back as {retain_until}, "
        f"drifted by {post_delta}s: got {post_expiry['RetainUntilDate']}"
    )

    try:
        s3.delete_object(Bucket=bucket, Key=key, VersionId=version_id)
    except ClientError as exc:
        # The window is judged on the local clock; a server clock behind it holds the lock a
        # little longer, so the same delete is retried (bounded) while it is still AccessDenied.
        if exc.response["Error"]["Code"] != "AccessDenied":
            raise
        retry_deadline = time.monotonic() + 15
        while True:
            time.sleep(1)
            try:
                s3.delete_object(Bucket=bucket, Key=key, VersionId=version_id)
                break
            except ClientError as again:
                code = again.response["Error"]["Code"]
                if code != "AccessDenied" or time.monotonic() > retry_deadline:
                    raise
    remaining = s3.list_object_versions(Bucket=bucket, Prefix=key).get("Versions", [])
    assert not any(v["VersionId"] == version_id for v in remaining), "version survived deletion after retention elapsed"

    # the delete is real, not just absent from a list: an independent op on the dead
    # version id returns the specific not-found code, and a further mutation on it fails too.
    gone_code, gone_message = _client_error(lambda: s3.get_object(Bucket=bucket, Key=key, VersionId=version_id))
    assert gone_code == "NoSuchVersion", f"expected NoSuchVersion reading the deleted version, got {gone_code!r}"
    assert gone_message == "The specified version does not exist.", f"unexpected message {gone_message!r}"
    retention_gone_code, retention_gone_message = _client_error(
        lambda: s3.get_object_retention(Bucket=bucket, Key=key, VersionId=version_id)
    )
    assert retention_gone_code == "NoSuchVersion", (
        f"expected NoSuchVersion querying retention on the deleted version, got {retention_gone_code!r}"
    )
    assert retention_gone_message == "The specified version does not exist.", (
        f"unexpected message {retention_gone_message!r}"
    )


def _create_bucket(ctx, **extra: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-retain-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    kwargs.update(extra)
    s3.create_bucket(**kwargs)

    def _cleanup() -> None:
        try:
            for v in s3.list_object_versions(Bucket=name).get("Versions", []):
                _best_effort(
                    lambda k=v["Key"], vid=v["VersionId"]: s3.delete_object(
                        Bucket=name, Key=k, VersionId=vid, BypassGovernanceRetention=True
                    )
                )
            for dm in s3.list_object_versions(Bucket=name).get("DeleteMarkers", []):
                _best_effort(
                    lambda k=dm["Key"], vid=dm["VersionId"]: s3.delete_object(Bucket=name, Key=k, VersionId=vid)
                )
            _best_effort(lambda: s3.delete_bucket(Bucket=name))
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its (Error.Code, Error.Message).
    An unexpected success raises, so accepting a refused call cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _best_effort(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
