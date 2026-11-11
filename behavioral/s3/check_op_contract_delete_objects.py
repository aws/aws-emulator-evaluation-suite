"""op-contract-delete-objects."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-objects"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteObjects batch-deletes versions; a retention-locked version fails per-key with AccessDenied."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx, object_lock=True)

    key_locked = "locked-object.txt"
    key_free = "free-object.txt"
    v_locked = s3.put_object(Bucket=bucket, Key=key_locked, Body=b"protected")["VersionId"]
    v_free = s3.put_object(Bucket=bucket, Key=key_free, Body=b"unprotected")["VersionId"]

    retain_until = datetime.now(timezone.utc) + timedelta(days=1)
    s3.put_object_retention(
        Bucket=bucket,
        Key=key_locked,
        VersionId=v_locked,
        Retention={"Mode": "GOVERNANCE", "RetainUntilDate": retain_until},
    )

    # --- success path + partial failure: batch delete of a locked version and a free version ---
    resp = s3.delete_objects(
        Bucket=bucket,
        Delete={
            "Objects": [
                {"Key": key_locked, "VersionId": v_locked},
                {"Key": key_free, "VersionId": v_free},
            ],
            "Quiet": False,
        },
    )
    deleted_keys = {(d["Key"], d.get("VersionId")) for d in resp.get("Deleted", [])}
    errors_by_key = {e["Key"]: e for e in resp.get("Errors", [])}

    assert (key_free, v_free) in deleted_keys, f"expected {key_free} deleted, got {resp.get('Deleted')}"
    assert key_locked in errors_by_key, f"expected {key_locked} to fail, got {resp.get('Errors')}"
    assert errors_by_key[key_locked]["Code"] == "AccessDenied", (
        f"expected AccessDenied for locked object, got {errors_by_key[key_locked]['Code']!r}"
    )
    assert errors_by_key[key_locked]["Message"] == "Access Denied because object protected by object lock.", (
        f"unexpected message {errors_by_key[key_locked]['Message']!r}"
    )
    assert key_locked not in {k for k, _ in deleted_keys}, (
        f"locked key must not appear among deleted keys, got {deleted_keys}"
    )

    # confirm the locked version genuinely still exists (delete was actually blocked, not just misreported)
    head = s3.head_object(Bucket=bucket, Key=key_locked, VersionId=v_locked)
    assert head["VersionId"] == v_locked, f"expected {key_locked} version {v_locked} to survive, got {head}"

    # --- restore leg: the same batch delete now succeeds once the block is lifted ---
    resp2 = s3.delete_objects(
        Bucket=bucket,
        Delete={"Objects": [{"Key": key_locked, "VersionId": v_locked}], "Quiet": False},
        BypassGovernanceRetention=True,
    )
    bypassed_keys = {(d["Key"], d.get("VersionId")) for d in resp2.get("Deleted", [])}
    assert (key_locked, v_locked) in bypassed_keys, (
        f"expected bypass delete of {key_locked} to succeed, got {resp2}"
    )
    # A HEAD response carries no body, so there is no AWS message to compare.
    code, _ = _client_error(lambda: s3.head_object(Bucket=bucket, Key=key_locked, VersionId=v_locked))
    assert code == "404", f"expected the bypassed version to be genuinely gone (404), got {code!r}"


def _client_error(fn):
    """The botocore (Error.Code, Error.Message) of fn(), the code falling back to the HTTP status
    for a code-less HEAD; RAISES if fn succeeds."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        code = err.get("Code")
        if not code or code.isdigit():
            code = str(e.response.get("ResponseMetadata", {}).get("HTTPStatusCode", "unknown"))
        return code, err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, object_lock: bool = False) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    if object_lock:
        kwargs["ObjectLockEnabledForBucket"] = True
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _force_delete_bucket(ctx, name))
    return name


def _force_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        try:
            for u in s3.list_multipart_uploads(Bucket=bucket).get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
                raise
        try:
            paginator = s3.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=bucket):
                objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
                objs += [{"Key": d["Key"], "VersionId": d["VersionId"]} for d in page.get("DeleteMarkers", [])]
                for i in range(0, len(objs), 1000):
                    batch = objs[i : i + 1000]
                    if not batch:
                        continue
                    try:
                        failed = s3.delete_objects(
                            Bucket=bucket, Delete={"Objects": batch}, BypassGovernanceRetention=True
                        ).get("Errors")
                        if failed:
                            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
                    except ClientError:
                        for o in batch:
                            try:
                                s3.delete_object(
                                    Bucket=bucket,
                                    Key=o["Key"],
                                    VersionId=o["VersionId"],
                                    BypassGovernanceRetention=True,
                                )
                            except ClientError as exc:
                                if exc.response["Error"]["Code"] not in (
                                    "NoSuchBucket",
                                    "NoSuchKey",
                                ):
                                    raise
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
