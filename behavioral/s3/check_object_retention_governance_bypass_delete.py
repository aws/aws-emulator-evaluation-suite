"""object-retention-governance-bypass-delete."""

from __future__ import annotations
import datetime
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "object-retention-governance-bypass-delete"
GROUP = 'object_lock'
SERVICES = ['s3']


def _delete_lock_bucket(client, bucket):
    """Empty an Object-Lock bucket (release legal holds + bypass GOVERNANCE) then delete it."""
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
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
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
    """The botocore (Error.Code, Error.Message) of fn(); RAISES if fn succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to fail and it succeeded")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GOVERNANCE-mode retained version cannot be deleted without
    BypassGovernanceRetention (AccessDenied), but CAN be deleted with it set."""
    s3 = ctx.client("s3")
    bucket = _new_lock_bucket(ctx, s3)

    # Positive control: an unretained version in the same bucket deletes normally, so the
    # AccessDenied below cannot be a target that rejects every DeleteObject call.
    control_key = "unretained.txt"
    control_version = s3.put_object(Bucket=bucket, Key=control_key, Body=b"unretained")["VersionId"]
    s3.delete_object(Bucket=bucket, Key=control_key, VersionId=control_version)
    control_gone, control_message = _client_error(
        lambda: s3.get_object(Bucket=bucket, Key=control_key, VersionId=control_version)
    )
    assert control_gone == "NoSuchVersion", f"expected the unretained control delete to stick, got {control_gone}"
    assert control_message == "The specified version does not exist.", (
        f"unexpected message {control_message!r}"
    )

    key = "governance.txt"
    version_id = s3.put_object(Bucket=bucket, Key=key, Body=b"gov-protected")["VersionId"]

    retain_until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
    s3.put_object_retention(
        Bucket=bucket,
        Key=key,
        Retention={"Mode": "GOVERNANCE", "RetainUntilDate": retain_until},
    )
    retention = s3.get_object_retention(Bucket=bucket, Key=key, VersionId=version_id)["Retention"]
    assert retention["Mode"] == "GOVERNANCE", f"retention did not land, got {retention!r}"

    code, message = _client_error(
        lambda: s3.delete_object(Bucket=bucket, Key=key, VersionId=version_id)
    )
    assert code == "AccessDenied", f"expected AccessDenied deleting GOVERNANCE-retained version without bypass, got {code}"
    assert message == "Access Denied because object protected by object lock.", (
        f"unexpected message {message!r}"
    )

    # Effect absent: the refused delete did not touch the version.
    intact = s3.get_object(Bucket=bucket, Key=key, VersionId=version_id)["Body"].read()
    assert intact == b"gov-protected", f"refused delete altered the object body, got {intact!r}"

    # With BypassGovernanceRetention=True (and the caller's implicit permission), it succeeds.
    s3.delete_object(
        Bucket=bucket, Key=key, VersionId=version_id, BypassGovernanceRetention=True
    )

    # Terminal independent read: the bypassed delete actually removed the version.
    gone_code, gone_message = _client_error(
        lambda: s3.get_object(Bucket=bucket, Key=key, VersionId=version_id)
    )
    assert gone_code == "NoSuchVersion", f"expected NoSuchVersion after bypass delete, got {gone_code}"
    assert gone_message == "The specified version does not exist.", f"unexpected message {gone_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
