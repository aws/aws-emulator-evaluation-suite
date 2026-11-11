"""s3checksum-presigned-put-query-malformed-base64-rejected."""

from __future__ import annotations

import base64
import binascii
import urllib.error
import urllib.request
from xml.etree import ElementTree

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3checksum-presigned-put-query-malformed-base64-rejected"
GROUP = "presigned-checksum"
SERVICES = ["s3"]

_MALFORMED_CRC32 = "not-valid-base64!!"
_BODY = b"presigned-checksum-query-malformed-base64-payload-" * 4


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
    """A presigned PUT URL whose signed ChecksumCRC32 is not valid base64 is refused InvalidRequest
    and stores nothing; a URL signed with a well-formed checksum for the same body succeeds.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    # Beat 1 — break exactly one thing: the signed checksum value is not valid base64.
    subject_key = "presigned/malformed.bin"
    subject_url = _presign_client(ctx).generate_presigned_url(
        "put_object",
        Params={
            "Bucket": bucket, "Key": subject_key,
            "ChecksumAlgorithm": "CRC32", "ChecksumCRC32": _MALFORMED_CRC32,
        },
        ExpiresIn=900,
    )
    signed = _signed_headers(subject_url)
    assert {"x-amz-checksum-crc32", "x-amz-sdk-checksum-algorithm"} <= signed, (
        f"X-Amz-SignedHeaders is {sorted(signed)!r}; expected it to bind both "
        "x-amz-checksum-crc32 and x-amz-sdk-checksum-algorithm into the signature"
    )

    status, body = _http(
        ctx, "PUT", subject_url,
        headers={"x-amz-checksum-crc32": _MALFORMED_CRC32, "x-amz-sdk-checksum-algorithm": "CRC32"},
        data=_BODY,
    )
    assert status == 400, (
        f"a presigned PUT signed with a non-base64 ChecksumCRC32 returned {status}, expected 400: "
        f"{body[:300]!r}"
    )
    assert _xml_error(body) == (
        "InvalidRequest", "Value for x-amz-checksum-crc32 header is invalid."
    ), f"the malformed-checksum refusal carries no InvalidRequest error: {body[:300]!r}"

    assert _error_code(lambda: s3.head_object(Bucket=bucket, Key=subject_key)) == "404", (
        f"{subject_key!r} exists after the presigned PUT signed with a malformed checksum"
    )

    # Beat 2 — positive control: a well-formed checksum for the same bytes, same mechanism.
    control_key = "presigned/control.bin"
    crc = base64.b64encode(binascii.crc32(_BODY).to_bytes(4, "big")).decode()
    control_url = _presign_client(ctx).generate_presigned_url(
        "put_object",
        Params={
            "Bucket": bucket, "Key": control_key,
            "ChecksumAlgorithm": "CRC32", "ChecksumCRC32": crc,
        },
        ExpiresIn=900,
    )
    status, body = _http(
        ctx, "PUT", control_url,
        headers={"x-amz-checksum-crc32": crc, "x-amz-sdk-checksum-algorithm": "CRC32"},
        data=_BODY,
    )
    assert status == 200, (
        f"the control presigned PUT, signed with a well-formed ChecksumCRC32 for the same body, "
        f"returned {status}: {body[:300]!r} — the refusal above was not about the mechanism"
    )
    head = s3.head_object(Bucket=bucket, Key=control_key, ChecksumMode="ENABLED")
    assert head.get("ChecksumCRC32") == crc, (
        f"the control object reports ChecksumCRC32={head.get('ChecksumCRC32')!r}, expected {crc!r}"
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
