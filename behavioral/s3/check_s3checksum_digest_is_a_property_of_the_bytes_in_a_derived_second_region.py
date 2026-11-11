"""s3checksum-digest-is-a-property-of-the-bytes-in-a-derived-second-region."""

from __future__ import annotations

import base64
import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3checksum-digest-is-a-property-of-the-bytes-in-a-derived-second-region"
GROUP = 'checksum-semantics'
SERVICES = ['s3']

_PAYLOAD = b"a-checksum-is-a-function-of-the-bytes-and-of-nothing-else-" * 96


def _delete_bucket(client, bucket):
    """Abort open uploads, empty a bucket (objects + versions + markers), then delete it."""
    try:
        for page in client.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                client.abort_multipart_upload(
                    Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"]
                )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
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


def _new_bucket_in(ctx, s3, region, **kwargs):
    """Create a uniquely-named bucket in ``region`` via ``s3``; register empty+delete teardown."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if region != "us-east-1":
        # us-east-1 is the one region CreateBucket rejects a LocationConstraint for.
        params["CreateBucketConfiguration"] = {"LocationConstraint": region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )
    return name


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


def _sha256_b64(data: bytes) -> str:
    """The base64 SHA-256 of ``data``, in the form S3 puts in ChecksumSHA256."""
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def _second_region(ctx) -> str:
    """A region other than ``ctx.region`` that the account can use, derived at runtime.

    Only opt-in-not-required regions qualify (an opted-out one answers with auth errors); the
    list is sorted so the choice is deterministic.
    """
    ec2 = ctx.client("ec2")
    regions = ec2.describe_regions()["Regions"]
    usable = sorted(
        r["RegionName"] for r in regions
        if r["RegionName"] != ctx.region and r.get("OptInStatus") == "opt-in-not-required"
    )
    assert usable, (
        f"describe_regions offered no enabled region other than {ctx.region!r}; the regions it "
        f"returned were {sorted((r['RegionName'], r.get('OptInStatus')) for r in regions)!r}"
    )
    return usable[0]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """The same bytes get the same SHA256, ETag and ChecksumType in a second region.

    A wrong SHA256 is refused there with BadDigest and stores nothing: the digest is a function of
    the bytes alone, and verification must not exist only at the default regional endpoint.
    """
    s3_home = ctx.client("s3")
    other = _second_region(ctx)
    assert other != ctx.region, f"the derived second region is {ctx.region!r} itself"
    s3_other = ctx.client("s3", region=other)

    want = _sha256_b64(_PAYLOAD)
    wrong = _sha256_b64(_PAYLOAD + b"x")
    assert wrong != want, "the wrong digest collided with the correct one"

    # --- The home-region object.
    home_bucket = _new_bucket_in(ctx, s3_home, ctx.region)
    home_put = s3_home.put_object(
        Bucket=home_bucket, Key="same-bytes.bin", Body=_PAYLOAD, ChecksumSHA256=want
    )
    assert home_put["ChecksumSHA256"] == want, (
        f"the {ctx.region} upload echoed {home_put['ChecksumSHA256']!r}, the client computed "
        f"{want!r}"
    )
    home_location = s3_home.get_bucket_location(Bucket=home_bucket).get("LocationConstraint")
    assert (home_location or "us-east-1") == ctx.region, (
        f"the home bucket reports LocationConstraint {home_location!r}, want {ctx.region!r}"
    )

    # --- The same bytes through the other region's endpoint.
    other_bucket = _new_bucket_in(ctx, s3_other, other)
    other_location = s3_other.get_bucket_location(Bucket=other_bucket).get("LocationConstraint")
    assert (other_location or "us-east-1") == other, (
        f"the second bucket reports LocationConstraint {other_location!r}, want {other!r}"
    )
    assert other_location != home_location, (
        f"both buckets report LocationConstraint {home_location!r}; the two uploads must go to "
        "genuinely different regions for this comparison to mean anything"
    )

    # --- Break exactly one thing, in the derived region: the digest value.
    exc = _client_error(
        lambda: s3_other.put_object(
            Bucket=other_bucket, Key="same-bytes.bin", Body=_PAYLOAD, ChecksumSHA256=wrong
        )
    )
    assert exc is not None, (
        f"the {other} endpoint accepted ChecksumSHA256={wrong!r} for a body whose true digest is "
        f"{want!r}; verification is wired up in {ctx.region} but not in {other}"
    )
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "BadDigest", (
        f"expected BadDigest for a mismatched SHA256 in {other}, got {code!r}"
    )
    message = exc.response.get("Error", {}).get("Message")
    assert message == "The SHA256 you specified did not match the calculated checksum.", (
        f"expected the exact BadDigest message for a mismatched SHA256 in {other}, got {message!r}"
    )
    assert status == 400, f"expected HTTP 400 for BadDigest in {other}, got {status!r}"

    # --- Effect absent, in that region.
    missing = _client_error(
        lambda: s3_other.head_object(Bucket=other_bucket, Key="same-bytes.bin")
    )
    assert missing is not None, f"the refused PutObject stored the object anyway in {other}"
    assert missing.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"HeadObject in {other} returned "
        f"{missing.response['ResponseMetadata']['HTTPStatusCode']!r}, expected 404"
    )
    listed = []
    for page in s3_other.get_paginator("list_objects_v2").paginate(Bucket=other_bucket):
        listed += [o["Key"] for o in page.get("Contents", [])]
    assert listed == [], f"the {other} bucket holds {listed!r} after the refused PUT"

    # --- POSITIVE CONTROL in the derived region, and the invariant across the two.
    other_put = s3_other.put_object(
        Bucket=other_bucket, Key="same-bytes.bin", Body=_PAYLOAD, ChecksumSHA256=want
    )
    assert other_put["ChecksumSHA256"] == want, (
        f"the {other} upload echoed {other_put['ChecksumSHA256']!r}, the client computed {want!r}"
    )
    home_got = s3_home.get_object(
        Bucket=home_bucket, Key="same-bytes.bin", ChecksumMode="ENABLED"
    )
    other_got = s3_other.get_object(
        Bucket=other_bucket, Key="same-bytes.bin", ChecksumMode="ENABLED"
    )
    home_body = home_got["Body"].read()
    other_body = other_got["Body"].read()
    assert home_body == other_body == _PAYLOAD, (
        f"the two regions returned {len(home_body)} and {len(other_body)} bytes; both must be the "
        f"{len(_PAYLOAD)} that were uploaded"
    )
    assert home_got["ChecksumSHA256"] == other_got["ChecksumSHA256"] == want, (
        f"{ctx.region} reports {home_got['ChecksumSHA256']!r} and {other} reports "
        f"{other_got['ChecksumSHA256']!r} for identical bytes; a checksum is a function of the "
        f"bytes alone and both must be {want!r}"
    )
    assert home_got["ChecksumType"] == other_got["ChecksumType"] == "FULL_OBJECT", (
        f"ChecksumType differs across regions: {home_got.get('ChecksumType')!r} in {ctx.region} "
        f"vs {other_got.get('ChecksumType')!r} in {other}"
    )
    assert home_got["ETag"] == other_got["ETag"], (
        f"the ETag of identical bytes differs across regions: {home_got['ETag']!r} vs "
        f"{other_got['ETag']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
