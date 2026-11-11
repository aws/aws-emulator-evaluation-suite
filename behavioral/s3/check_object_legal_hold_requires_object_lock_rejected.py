"""object-legal-hold-requires-object-lock-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-legal-hold-requires-object-lock-rejected"
GROUP = "state-machine"
SERVICES = ["s3"]
NOT_LOCK_ENABLED_MESSAGE = 'Bucket is missing Object Lock Configuration'


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutObjectLegalHold on a bucket created without Object Lock is rejected with InvalidRequest and
    its exact message, while the same call on a twin Object-Lock-enabled bucket sets the hold ON."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-legalholdneg-")
    key = "legal-hold-negative-test.txt"
    _create_bucket(ctx, s3, name)  # note: no ObjectLockEnabledForBucket
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))

    s3.put_object(Bucket=name, Key=key, Body=b"no-object-lock-payload")

    code, message = _error(
        lambda: s3.put_object_legal_hold(Bucket=name, Key=key, LegalHold={"Status": "ON"})
    )
    assert code == "InvalidRequest", code
    assert message == NOT_LOCK_ENABLED_MESSAGE, f"unexpected InvalidRequest message: {message!r}"

    # GetObjectLegalHold on the same bucket errors out too (no lock configuration
    # at all) -- real S3 reports this the same way as the Put call, as
    # InvalidRequest, since the bucket itself was never Object-Lock-enabled
    # (NoSuchObjectLockConfiguration is what get_object_lock_configuration
    # returns for a *different*, lock-enabled bucket that lacks a configured
    # default retention, which does not apply here).
    code2, message2 = _error(lambda: s3.get_object_legal_hold(Bucket=name, Key=key))
    assert code2 == "InvalidRequest", code2
    assert message2 == NOT_LOCK_ENABLED_MESSAGE, f"unexpected InvalidRequest message: {message2!r}"

    # Positive control: the identical calls succeed on a bucket that IS
    # Object-Lock-enabled, so the rejection above is provably tied to the missing
    # lock configuration rather than to the operation being unconditionally refused.
    lock_name = ctx.unique_name("sim2real-behav-legalholdpos-")
    _create_bucket(ctx, s3, lock_name, ObjectLockEnabledForBucket=True)
    ctx.on_cleanup(lambda: _empty_and_delete_lock_bucket(s3, lock_name))

    s3.put_object(Bucket=lock_name, Key=key, Body=b"has-object-lock-payload")
    s3.put_object_legal_hold(Bucket=lock_name, Key=key, LegalHold={"Status": "ON"})
    held = s3.get_object_legal_hold(Bucket=lock_name, Key=key)["LegalHold"]
    assert held["Status"] == "ON", f"expected legal hold ON on a lock-enabled bucket, got {held!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, s3, name: str, **kwargs) -> None:
    params: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)


def _empty_and_delete_bucket(s3, name: str, bypass_governance: bool = False) -> None:
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            to_delete = []
            for v in page.get("Versions", []):
                to_delete.append({"Key": v["Key"], "VersionId": v["VersionId"]})
            for m in page.get("DeleteMarkers", []):
                to_delete.append({"Key": m["Key"], "VersionId": m["VersionId"]})
            if to_delete:
                kwargs = {"Bucket": name, "Delete": {"Objects": to_delete}}
                if bypass_governance:
                    kwargs["BypassGovernanceRetention"] = True
                failed = s3.delete_objects(**kwargs).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _empty_and_delete_lock_bucket(s3, name: str) -> None:
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            for v in page.get("Versions", []):
                key, vid = v["Key"], v["VersionId"]
                try:
                    s3.put_object_legal_hold(
                        Bucket=name, Key=key, VersionId=vid, LegalHold={"Status": "OFF"}
                    )
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
                try:
                    s3.delete_object(
                        Bucket=name, Key=key, VersionId=vid, BypassGovernanceRetention=True
                    )
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
            for m in page.get("DeleteMarkers", []):
                try:
                    s3.delete_object(Bucket=name, Key=m["Key"], VersionId=m["VersionId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
