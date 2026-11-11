"""range-read-unsatisfiable-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "range-read-unsatisfiable-rejected"
GROUP = 'range_reads'
SERVICES = ['s3']

_SIZE = 100


# ===== helpers (self-contained) =====
def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
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


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None
# ===== end helpers =====


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An unsatisfiable Range is 416 InvalidRange; an over-long Range is clamped and an unparseable one is
    ignored (200, whole object). The 416 carries no Content-Range header, so the object size needs a
    separate HeadObject.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "range-target.bin"
    body = bytes(i % 256 for i in range(_SIZE))
    s3.put_object(Bucket=bucket, Key=key, Body=body)

    # --- Control: a fully satisfiable range is a 206 with exactly the requested window.
    resp = s3.get_object(Bucket=bucket, Key=key, Range="bytes=10-19")
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 206, (
        f"a satisfiable range must be 206, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    assert resp["Body"].read() == body[10:20]
    assert resp["ContentRange"] == f"bytes 10-19/{_SIZE}", (
        f"unexpected ContentRange {resp['ContentRange']!r}"
    )

    # --- CLAMPED, not rejected: last-byte-pos beyond EOF is legal and truncates to EOF.
    resp = s3.get_object(Bucket=bucket, Key=key, Range=f"bytes=90-{_SIZE * 10}")
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 206, (
        "a range whose END exceeds the object size must be CLAMPED to a 206, not rejected; got "
        f"{resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    assert resp["Body"].read() == body[90:], "an over-long range must return bytes 90..EOF"
    assert resp["ContentRange"] == f"bytes 90-{_SIZE - 1}/{_SIZE}", (
        f"an over-long range must report the clamped window, got {resp['ContentRange']!r}"
    )
    assert resp["ContentLength"] == 10, f"expected 10 clamped bytes, got {resp['ContentLength']}"

    # --- Break exactly one thing: first-byte-pos AT the object size is unsatisfiable.
    exc = _client_error(lambda: s3.get_object(Bucket=bucket, Key=key, Range=f"bytes={_SIZE}-"))
    assert exc is not None, (
        f"a range starting at byte {_SIZE} of a {_SIZE}-byte object was accepted; an unsatisfiable "
        "range must be refused, not answered with an empty body"
    )
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "InvalidRange", f"expected InvalidRange, got {code!r}"
    assert status == 416, f"expected HTTP 416 for InvalidRange, got {status!r}"
    assert (
        exc.response.get("Error", {}).get("Message") == "The requested range is not satisfiable"
    ), (
        f"the 416 body must attribute itself to the range; real AWS says exactly \"The requested "
        f"range is not satisfiable\" and this said "
        f"{exc.response.get('Error', {}).get('Message')!r}"
    )
    headers = exc.response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
    # On real AWS S3's 416 carries NO Content-Range header.
    # The full header set on the refusal is x-amz-request-id, x-amz-id-2, content-type,
    # transfer-encoding, date, server — nothing else. RFC 7233 §4.4 says a 416 SHOULD send
    # "Content-Range: bytes */<complete-length>", and S3 does not, so a client CANNOT learn the
    # object's real size from the refusal and must issue a separate HeadObject (asserted at the
    # end of this check). Pinned as an absence on purpose: an emulator built from the RFC rather
    # than from S3 will helpfully add the header, and code that reads `Content-Range` off a 416
    # to discover the size then works locally and breaks against AWS.
    assert "content-range" not in headers, (
        f"real S3 sends no Content-Range on a 416, got {headers.get('content-range')!r}; the size "
        f"is discoverable only via HeadObject"
    )
    assert headers.get("content-type") == "application/xml", (
        f"the 416 is an XML error document, got {headers.get('content-type')!r}"
    )

    # --- The same unsatisfiable range on HEAD: also 416, but with no body to parse, so the code
    # is the bare status rather than InvalidRange.
    exc_head = _client_error(
        lambda: s3.head_object(Bucket=bucket, Key=key, Range=f"bytes={_SIZE + 500}-{_SIZE + 600}")
    )
    assert exc_head is not None, "HeadObject with an unsatisfiable range succeeded"
    assert exc_head.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 416, (
        f"HeadObject must refuse an unsatisfiable range with 416 too, got "
        f"{exc_head.response.get('ResponseMetadata', {}).get('HTTPStatusCode')!r}"
    )
    assert (
        "content-range"
        not in exc_head.response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
    ), "the HEAD 416 sends no Content-Range either"

    # --- Same class, past the end rather than at it: still 416, not a 200 or a 404.
    exc = _client_error(
        lambda: s3.get_object(Bucket=bucket, Key=key, Range=f"bytes={_SIZE + 500}-{_SIZE + 600}")
    )
    assert exc is not None, "a range entirely past EOF was accepted"
    assert exc.response.get("Error", {}).get("Code") == "InvalidRange", (
        f"expected InvalidRange for a range entirely past EOF, got "
        f"{exc.response.get('Error', {}).get('Code')!r}"
    )

    # --- IGNORED, not rejected: an unparseable Range header yields the whole object.
    resp = s3.get_object(Bucket=bucket, Key=key, Range="bytes=not-a-range")
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        "an unparseable Range header must be ignored and answered with a full 200, got "
        f"{resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    assert resp["Body"].read() == body, "an ignored Range must return the complete object"
    assert "ContentRange" not in resp, (
        f"a full 200 response must not carry ContentRange, got {resp.get('ContentRange')!r}"
    )

    # --- Effect absent / control still works: the rejections did not disturb the object, and
    # HeadObject is the ONLY way to recover the size the 416 refused to disclose.
    assert s3.get_object(Bucket=bucket, Key=key)["Body"].read() == body
    assert s3.head_object(Bucket=bucket, Key=key)["ContentLength"] == _SIZE


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
