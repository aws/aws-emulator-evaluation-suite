"""list-object-versions-pages-one-key-written-more-than-one-thousand-times."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-object-versions-pages-one-key-written-more-than-one-thousand-times"
GROUP = "versioned-delete"
SERVICES = ["s3"]

_WRITES = 1001
_PAGE = 1000
_KEY = "hot/key.txt"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """One key written 1,001 times keeps 1,001 versions, listed newest first in pages of 1,000.

    The truncated first page's version markers return the oldest version on the second page.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectVersions.html
    """
    s3 = ctx.client("s3")
    bucket = _bucket(ctx)
    written = []
    for i in range(_WRITES):
        written.append(s3.put_object(Bucket=bucket, Key=_KEY, Body=f"v{i}".encode())["VersionId"])
    assert len(set(written)) == _WRITES, (
        f"{_WRITES} writes must return distinct VersionIds; got {len(set(written))}"
    )
    newest_first = written[::-1]

    first = s3.list_object_versions(Bucket=bucket)
    first_ids = [v["VersionId"] for v in first.get("Versions") or []]
    assert first["MaxKeys"] == _PAGE, (
        f"the default MaxKeys must be {_PAGE}; got {first['MaxKeys']!r}"
    )
    assert first_ids == newest_first[:_PAGE], (
        f"the first page must hold the newest {_PAGE} versions, newest first; "
        f"got {len(first_ids)} versions"
    )
    assert [v["IsLatest"] for v in first["Versions"]] == [True] + [False] * (_PAGE - 1), (
        "only the newest version may be IsLatest"
    )
    assert first["IsTruncated"] is True, (
        f"the first page must be truncated; got {first['IsTruncated']!r}"
    )
    assert (first.get("NextKeyMarker"), first.get("NextVersionIdMarker")) == (
        _KEY,
        newest_first[_PAGE - 1],
    ), (
        "the markers must name the key and the last version listed; got "
        f"{(first.get('NextKeyMarker'), first.get('NextVersionIdMarker'))!r}"
    )

    second = s3.list_object_versions(
        Bucket=bucket,
        KeyMarker=first["NextKeyMarker"],
        VersionIdMarker=first["NextVersionIdMarker"],
    )
    second_ids = [v["VersionId"] for v in second.get("Versions") or []]
    assert second_ids == newest_first[_PAGE:], (
        f"the second page must hold only the oldest version {newest_first[_PAGE:]!r}; "
        f"got {second_ids!r}"
    )
    assert second["IsTruncated"] is False, (
        f"the last page must not be truncated; got {second['IsTruncated']!r}"
    )

    oldest = s3.get_object(Bucket=bucket, Key=_KEY, VersionId=written[0])["Body"].read()
    assert oldest == b"v0", f"the oldest version must still read its own body; got {oldest!r}"


def _bucket(ctx) -> str:
    """A versioned bucket whose purge-and-delete net is registered before the create."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-hotkey-")
    ctx.on_cleanup(lambda: _drop_bucket(ctx, name))
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is S3's default region: CreateBucket rejects an explicit LocationConstraint
        # there, so it must be omitted rather than passed.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    return name


def _drop_bucket(ctx, bucket: str) -> None:
    """The cleanup: delete every version and marker, then the bucket; a missing bucket is fine."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in (page.get("Versions") or []) + (page.get("DeleteMarkers") or [])
            ]
            if objs:
                out = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
                if out.get("Errors"):
                    raise AssertionError(f"cleanup could not delete {out['Errors'][:3]!r}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
