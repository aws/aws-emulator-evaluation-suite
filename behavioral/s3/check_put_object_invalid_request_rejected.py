"""put-object-invalid-request-rejected."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-object-invalid-request-rejected"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject with Object Lock headers on a bucket without Object Lock fails with InvalidRequest 'Bucket
    is missing ObjectLockConfiguration' and creates nothing, while on an Object-Lock-enabled bucket it
    succeeds and the GOVERNANCE retention reads back."""
    s3 = ctx.client("s3")
    retain_until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)

    plain_bucket = ctx.unique_name("sim2real-behav-nolock-")
    _create_bucket(s3, plain_bucket, ctx.region)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=plain_bucket))

    key = "locked-object.txt"
    code = _error_code(
        lambda: s3.put_object(
            Bucket=plain_bucket,
            Key=key,
            Body=b"payload",
            ObjectLockMode="GOVERNANCE",
            ObjectLockRetainUntilDate=retain_until,
        )
    )
    assert code == ("InvalidRequest", "Bucket is missing ObjectLockConfiguration"), f"expected InvalidRequest, got {code!r}"

    # The rejected write must not have created the object.
    listing = s3.list_objects_v2(Bucket=plain_bucket)
    assert listing.get("KeyCount", 0) == 0, f"expected empty bucket, got KeyCount={listing.get('KeyCount')!r}"
    assert "Contents" not in listing, f"expected no Contents, got {listing.get('Contents')!r}"

    # Positive control: the same request succeeds on a bucket with Object Lock enabled.
    locked_bucket = ctx.unique_name("sim2real-behav-lock-")
    _create_bucket(s3, locked_bucket, ctx.region, ObjectLockEnabledForBucket=True)

    def _cleanup_locked_bucket() -> None:
        head = s3.list_object_versions(Bucket=locked_bucket).get("Versions", [])
        for version in head:
            s3.delete_object(
                Bucket=locked_bucket,
                Key=version["Key"],
                VersionId=version["VersionId"],
                BypassGovernanceRetention=True,
            )
        s3.delete_bucket(Bucket=locked_bucket)

    ctx.on_cleanup(_cleanup_locked_bucket)

    put_result = s3.put_object(
        Bucket=locked_bucket,
        Key=key,
        Body=b"payload",
        ObjectLockMode="GOVERNANCE",
        ObjectLockRetainUntilDate=retain_until,
    )
    version_id = put_result["VersionId"]
    head = s3.head_object(Bucket=locked_bucket, Key=key, VersionId=version_id)
    assert head["ObjectLockMode"] == "GOVERNANCE", f"expected ObjectLockMode=GOVERNANCE, got {head.get('ObjectLockMode')!r}"
    assert head["ObjectLockRetainUntilDate"].date() == retain_until.date(), (
        f"expected retain-until date {retain_until.date()}, got {head['ObjectLockRetainUntilDate'].date()}"
    )


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_bucket(s3, bucket: str, region: str, **kwargs) -> None:
    if region and region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}, **kwargs)
    else:
        s3.create_bucket(Bucket=bucket, **kwargs)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
