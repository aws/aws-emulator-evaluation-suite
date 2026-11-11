"""list-multipart-uploads-paginates-and-groups-common-prefixes."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-multipart-uploads-paginates-and-groups-common-prefixes"
GROUP = "multipart"
SERVICES = ["s3"]

_FLAT_KEYS = ["flat1", "flat2", "flat3", "flat4", "flat5"]
_DIR_KEYS = ["dirA/k1", "dirB/k2"]
_MAX_UPLOADS = 2


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListMultipartUploads with Delimiter groups uploads under a common prefix into CommonPrefixes
    and lists only the flat keys; with MaxUploads and no delimiter, KeyMarker/UploadIdMarker
    continuation returns every in-progress upload exactly once, in Key order."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    for key in sorted(_FLAT_KEYS + _DIR_KEYS):
        uid = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
        ctx.on_cleanup(_teardown(
            lambda key=key, uid=uid: s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=uid),
            "NoSuchUpload",
        ))

    delim = s3.list_multipart_uploads(Bucket=bucket, Delimiter="/", MaxUploads=10)
    assert delim["IsTruncated"] is False, f"expected a single page, got {delim!r}"
    listed_flat = sorted(u["Key"] for u in delim.get("Uploads", []))
    assert listed_flat == sorted(_FLAT_KEYS), (
        f"Delimiter='/' must list only the flat keys as Uploads; got {listed_flat!r}"
    )
    prefixes = sorted(p["Prefix"] for p in delim.get("CommonPrefixes", []))
    assert prefixes == ["dirA/", "dirB/"], (
        f"Delimiter='/' must group the nested keys into CommonPrefixes; got {prefixes!r}"
    )

    all_keys = sorted(_FLAT_KEYS + _DIR_KEYS)
    seen: list[str] = []
    key_marker, upload_id_marker = None, None
    pages = 0
    truncated = True
    while truncated:
        kwargs = {"Bucket": bucket, "MaxUploads": _MAX_UPLOADS}
        if key_marker is not None:
            kwargs["KeyMarker"] = key_marker
            kwargs["UploadIdMarker"] = upload_id_marker
        resp = s3.list_multipart_uploads(**kwargs)
        pages += 1
        assert pages <= len(all_keys), (
            f"pagination did not converge after {pages} pages: seen {seen!r}"
        )
        page_keys = [u["Key"] for u in resp.get("Uploads", [])]
        assert len(page_keys) <= _MAX_UPLOADS, (
            f"page returned {len(page_keys)} uploads, more than MaxUploads={_MAX_UPLOADS}: {page_keys!r}"
        )
        seen.extend(page_keys)
        truncated = resp["IsTruncated"]
        if truncated:
            next_key_marker = resp.get("NextKeyMarker")
            next_upload_id_marker = resp.get("NextUploadIdMarker")
            assert next_key_marker, f"IsTruncated=True but NextKeyMarker is empty: {resp!r}"
            key_marker, upload_id_marker = next_key_marker, next_upload_id_marker

    assert seen == all_keys, (
        f"paginating ListMultipartUploads with MaxUploads={_MAX_UPLOADS} and KeyMarker/"
        f"UploadIdMarker continuation must return every upload exactly once, in Key order; "
        f"got {seen!r}"
    )


def _new_bucket(ctx, s3) -> str:
    """Create a uniquely-named bucket and register its teardown."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=name), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
