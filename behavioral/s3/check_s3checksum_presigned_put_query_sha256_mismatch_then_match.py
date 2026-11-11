"""s3checksum-presigned-put-query-sha256-mismatch-then-match."""

from __future__ import annotations

import base64
import hashlib
import urllib.error
import urllib.request
from xml.etree import ElementTree

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3checksum-presigned-put-query-sha256-mismatch-then-match"
GROUP = "presigned-checksum"
SERVICES = ["s3"]

_BODY_A = b"presigned-checksum-query-sha256-body-a-" * 4
_BODY_B = b"presigned-checksum-query-sha256-body-b-different-bytes-" * 4


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A presigned PUT URL signing ChecksumSHA256 in its query refuses a body that does not match
    it with BadDigest and stores nothing; the body it was signed for is accepted and read back
    under that same SHA256.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "presigned/sha256.bin"
    sha_a = base64.b64encode(hashlib.sha256(_BODY_A).digest()).decode()
    headers = {"x-amz-checksum-sha256": sha_a, "x-amz-sdk-checksum-algorithm": "SHA256"}

    url = _presign_client(ctx).generate_presigned_url(
        "put_object",
        Params={
            "Bucket": bucket, "Key": key,
            "ChecksumAlgorithm": "SHA256", "ChecksumSHA256": sha_a,
        },
        ExpiresIn=900,
    )
    signed = _signed_headers(url)
    assert {"x-amz-checksum-sha256", "x-amz-sdk-checksum-algorithm"} <= signed, (
        f"X-Amz-SignedHeaders is {sorted(signed)!r}; expected it to bind both "
        "x-amz-checksum-sha256 and x-amz-sdk-checksum-algorithm into the signature"
    )

    # Beat 1 — the same signed URL, a body the signed checksum does not describe.
    status, body = _http(ctx, "PUT", url, headers=headers, data=_BODY_B)
    assert status == 400, (
        f"PUTting a body other than the one ChecksumSHA256={sha_a!r} was signed for returned "
        f"{status}, expected 400: {body[:300]!r}"
    )
    assert _xml_error(body) == (
        "BadDigest", "The SHA256 you specified did not match the calculated checksum."
    ), f"the mismatched-body refusal carries no BadDigest error: {body[:300]!r}"

    assert _error_code(lambda: s3.head_object(Bucket=bucket, Key=key)) == "404", (
        f"{key!r} exists after the presigned PUT whose body did not match its signed SHA256"
    )

    # Beat 2 — the identical URL, the body its checksum actually describes.
    status, body = _http(ctx, "PUT", url, headers=headers, data=_BODY_A)
    assert status == 200, (
        f"the same presigned URL, PUT with the body its ChecksumSHA256 was signed for, returned "
        f"{status}: {body[:300]!r}"
    )

    head = s3.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    assert head.get("ChecksumSHA256") == sha_a, (
        f"HeadObject reports ChecksumSHA256={head.get('ChecksumSHA256')!r}, expected {sha_a!r}"
    )
    got = s3.get_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    got_body = got["Body"].read()
    assert got_body == _BODY_A, f"stored body is {got_body!r}, expected {_BODY_A!r}"
    assert got.get("ChecksumSHA256") == sha_a, (
        f"GetObject reports ChecksumSHA256={got.get('ChecksumSHA256')!r}, expected {sha_a!r}"
    )


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; teardown only."""
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


def _new_bucket(ctx, s3):
    """Create a uniquely-named, tagged bucket; register empty+delete teardown; return its name."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":  # region-pinned: CreateBucket rejects LocationConstraint there
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"},
                            {"Key": "sim2real:check", "Value": CHECK}]},
    )
    return name


def _presign_client(ctx):
    """An S3 client for presigned URLs: SigV4 (s3v4) + virtual-hosted addressing.

    Without s3v4 the default presigner may emit query auth with no X-Amz-SignedHeaders; virtual
    addressing pins the regional host (no 307).
    """
    from botocore.config import Config

    cfg = Config(
        signature_version="s3v4",
        s3={"addressing_style": "virtual"},
        retries={"max_attempts": 1},
    )
    return ctx.client("s3", config=cfg)


def _signed_headers(url: str) -> set[str]:
    """The lowercase header names X-Amz-SignedHeaders binds into a presigned URL's signature."""
    from urllib.parse import parse_qs, urlsplit

    query = parse_qs(urlsplit(url).query)
    values = query.get("X-Amz-SignedHeaders", [""])[0]
    return set(values.split(";"))


def _error_code(fn) -> str:
    """The botocore Error.Code (or HTTP status for a code-less HEAD) of fn(); RAISES if fn succeeds."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code and not code.isdigit():
            return code
        return str(exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", "unknown"))
    raise AssertionError("the call was expected to fail and it succeeded")


def _xml_error(body: bytes) -> tuple[str | None, str | None]:
    """The (Code, Message) of an S3 XML error body; None for a part the body does not carry."""
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return None, None
    return root.findtext("Code"), root.findtext("Message")


def _http(ctx, method: str, url: str, headers=None, data=None):
    """Raw HTTP to ``url`` on the target; returns (status, body). 4xx/5xx are answers, not errors."""
    target, route = ctx.endpoint_route(url)
    req = urllib.request.Request(target, method=method, data=data)
    for k, v in {**route, **(headers or {})}.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=60, context=_ssl_context(ctx.http_verify)) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
