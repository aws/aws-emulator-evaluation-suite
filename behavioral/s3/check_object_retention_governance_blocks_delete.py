"""object-retention-governance-blocks-delete."""

from __future__ import annotations
import datetime
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "object-retention-governance-blocks-delete"
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
    """DeleteObject on a version under active GOVERNANCE retention must fail without
    BypassGovernanceRetention (overly-permissive boundary); the retained version survives
    the refusal untouched, and is verified truly gone only once bypass is granted."""
    s3 = ctx.client("s3")
    name = _new_lock_bucket(ctx, s3)

    # Positive control: an unretained version in this same bucket deletes normally, so the
    # AccessDenied below can be attributed to the retention and not to a broken bucket/principal.
    control_key = "unretained.txt"
    control_version = s3.put_object(Bucket=name, Key=control_key, Body=b"control")["VersionId"]
    s3.delete_object(Bucket=name, Key=control_key, VersionId=control_version)
    control_code, control_message = _client_error(
        lambda: s3.get_object(Bucket=name, Key=control_key, VersionId=control_version)
    )
    assert control_code == "NoSuchVersion", (
        f"positive control: deleting an unretained version should leave it gone, got {control_code!r}"
    )
    assert control_message == "The specified version does not exist.", (
        f"unexpected message {control_message!r}"
    )

    key = "retained.txt"
    put = s3.put_object(Bucket=name, Key=key, Body=b"locked")
    version_id = put["VersionId"]

    retain_until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
    s3.put_object_retention(
        Bucket=name, Key=key, VersionId=version_id,
        Retention={"Mode": "GOVERNANCE", "RetainUntilDate": retain_until},
    )

    code, message = _client_error(lambda: s3.delete_object(Bucket=name, Key=key, VersionId=version_id))
    assert code == "AccessDenied", f"expected AccessDenied deleting a retained version, got {code!r}"
    assert message == "Access Denied because object protected by object lock.", (
        f"unexpected message {message!r}"
    )

    # effect absent: the refused delete must not have touched the retained version
    survivor = s3.get_object(Bucket=name, Key=key, VersionId=version_id)["Body"].read()
    assert survivor == b"locked", f"the refused delete altered the retained version, got {survivor!r}"

    # with bypass, deletion must succeed (requires s3:BypassGovernanceRetention, granted to the test principal)
    s3.delete_object(
        Bucket=name, Key=key, VersionId=version_id, BypassGovernanceRetention=True
    )

    # terminal read at the destination, through a different operation than the one that mutated
    gone, gone_message = _client_error(lambda: s3.get_object(Bucket=name, Key=key, VersionId=version_id))
    assert gone == "NoSuchVersion", f"expected NoSuchVersion after the bypass delete, got {gone!r}"
    assert gone_message == "The specified version does not exist.", f"unexpected message {gone_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
