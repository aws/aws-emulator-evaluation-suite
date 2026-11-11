"""conc-s3-conditional-writes-versioned-noncurrent-etag-if-match-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-s3-conditional-writes-versioned-noncurrent-etag-if-match-rejected"
GROUP = 'conditional-rejection'
SERVICES = ['s3']

_V1 = b"version-one-now-noncurrent-but-still-stored"
_V2 = b"version-two-the-current-version"
_V3 = b"version-three-written-by-a-correct-compare-and-swap"
_STALE = b"stale-writer-payload-that-must-never-become-a-version"
_PRECONDITION_MSG = 'At least one of the pre-conditions you specified did not hold'


def _delete_bucket(s3, bucket):
    """Abort uploads, empty every version and marker, then delete the bucket (raises if it cannot)."""
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-condw-")
    params = {"Bucket": name}
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; not a region pin.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _client_error(fn, refused="the call succeeded; AWS refuses it with a ClientError"):
    """Call fn(); return the ClientError it raised. A call that succeeds fails the check."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError(refused)


def _all_versions(s3, bucket):
    versions, markers = [], []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        versions += page.get("Versions", [])
        markers += page.get("DeleteMarkers", [])
    return versions, markers


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """On a versioned bucket, PutObject If-Match naming a noncurrent version's ETag is refused with 412
    PreconditionFailed and its exact message and adds no version; naming the current ETag appends a new
    current version while the older versions keep their bytes."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    assert s3.get_bucket_versioning(Bucket=bucket).get("Status") == "Enabled", (
        "versioning did not take effect on the bucket"
    )
    key = "cas/versioned.txt"

    r1 = s3.put_object(Bucket=bucket, Key=key, Body=_V1)
    r2 = s3.put_object(Bucket=bucket, Key=key, Body=_V2)
    assert r1["ETag"] != r2["ETag"] and r1["VersionId"] != r2["VersionId"], (
        f"setup versions are not distinct: {r1['ETag']!r}/{r1['VersionId']!r} vs "
        f"{r2['ETag']!r}/{r2['VersionId']!r}"
    )

    # --- Break exactly one thing: condition on v1's (stored but noncurrent) ETag.
    exc = _client_error(lambda: s3.put_object(Bucket=bucket, Key=key, Body=_STALE,
                                              IfMatch=r1["ETag"]),
                        f"If-Match with noncurrent v1 ETag {r1['ETag']!r} succeeded; the "
                        "precondition is being checked against version history instead of the "
                        "current version")
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "PreconditionFailed", f"expected PreconditionFailed, got {code!r}"
    message = exc.response.get("Error", {}).get("Message")
    assert message == _PRECONDITION_MSG, (
        f"expected message {_PRECONDITION_MSG!r}, got {message!r}"
    )
    assert status == 412, f"expected HTTP 412, got {status!r}"

    # --- Effect absent: exactly v1 and v2 exist, v2 is current and byte-exact.
    versions, markers = _all_versions(s3, bucket)
    ids = sorted(v["VersionId"] for v in versions)
    assert ids == sorted([r1["VersionId"], r2["VersionId"]]), (
        f"after the refused write ListObjectVersions reports {ids!r}; want exactly v1 and v2"
    )
    assert markers == [], f"the refused write created delete markers: {markers!r}"
    current = s3.get_object(Bucket=bucket, Key=key)
    assert current["Body"].read() == _V2 and current["VersionId"] == r2["VersionId"], (
        f"current version is {current['VersionId']!r}; want untouched v2 {r2['VersionId']!r}"
    )

    # --- POSITIVE CONTROL: If-Match with the CURRENT ETag appends v3.
    r3 = s3.put_object(Bucket=bucket, Key=key, Body=_V3, IfMatch=r2["ETag"])
    assert r3["VersionId"] not in (r1["VersionId"], r2["VersionId"]), (
        f"the conditional write reported VersionId {r3['VersionId']!r}, reusing an old version"
    )
    now = s3.get_object(Bucket=bucket, Key=key)
    assert now["Body"].read() == _V3 and now["VersionId"] == r3["VersionId"], (
        f"read-after-write returned version {now['VersionId']!r}; want new v3 {r3['VersionId']!r}"
    )
    versions, _ = _all_versions(s3, bucket)
    ids = sorted(v["VersionId"] for v in versions)
    want = sorted([r1["VersionId"], r2["VersionId"], r3["VersionId"]])
    assert ids == want, f"ListObjectVersions reports {ids!r}; want {want!r}"
    latest = [v["VersionId"] for v in versions if v["IsLatest"]]
    assert latest == [r3["VersionId"]], f"latest is {latest!r}; want [{r3['VersionId']!r}]"
    for rid, body in ((r1["VersionId"], _V1), (r2["VersionId"], _V2)):
        old = s3.get_object(Bucket=bucket, Key=key, VersionId=rid)["Body"].read()
        assert old == body, f"version {rid!r} now holds {old!r}; want {body!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
