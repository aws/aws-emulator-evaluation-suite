"""s3-chunked-upload-trailer-checksum-mismatch-rejected-object-absent."""
from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import hmac
import ssl
import urllib.error
import urllib.parse
import urllib.request
from xml.etree import ElementTree

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-chunked-upload-trailer-checksum-mismatch-rejected-object-absent"
GROUP = "chunked-upload"
SERVICES = ["s3"]


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An aws-chunked STREAMING-UNSIGNED-PAYLOAD-TRAILER PUT whose trailer carries a CRC32 value
    that does not match the uploaded bytes is refused with BadDigest and stores nothing; the
    same upload with the correct trailer value succeeds.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    payload = b"trailer-checksum-mismatch-payload-bytes-" * 50
    good_crc32 = base64.b64encode(binascii.crc32(payload).to_bytes(4, "big")).decode()
    wrong_crc32 = base64.b64encode((binascii.crc32(payload) ^ 0xFFFFFFFF).to_bytes(4, "big")).decode()
    assert wrong_crc32 != good_crc32, "the corrupted CRC32 must differ from the correct one"

    bad_key = "chunked/trailer-mismatch.bin"
    status, body = _put_unsigned_trailer(
        ctx, bucket, bad_key, payload, "x-amz-checksum-crc32", wrong_crc32
    )
    assert status == 400, (
        f"a trailer CRC32 that does not match the payload must be refused 400, got {status}: "
        f"{body[:300]!r}"
    )
    assert _xml_error(body) == (
        "BadDigest", "The CRC32 you specified did not match the calculated checksum."
    ), f"the mismatched-trailer refusal carries no BadDigest error: {body[:300]!r}"

    code, message = _error_code(lambda: s3.get_object(Bucket=bucket, Key=bad_key))
    assert code == "NoSuchKey", f"{bad_key!r} must not exist after the rejected PUT, got {code!r}"
    assert message == "The specified key does not exist.", (
        f"get_object of the absent key must say 'The specified key does not exist.', got {message!r}"
    )

    # Positive control: the identical request shape, trailer value the bytes actually produce.
    good_key = "chunked/trailer-ok-control.bin"
    status, body = _put_unsigned_trailer(
        ctx, bucket, good_key, payload, "x-amz-checksum-crc32", good_crc32
    )
    assert status == 200, (
        f"the same upload with the correct trailer checksum must succeed, got {status}: {body[:300]!r}"
    )
    head = s3.head_object(Bucket=bucket, Key=good_key, ChecksumMode="ENABLED")
    assert head.get("ChecksumCRC32") == good_crc32, (
        f"the control object's ChecksumCRC32 is {head.get('ChecksumCRC32')!r}, expected {good_crc32!r}"
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
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]},
    )
    return name


def _signing_creds(ctx):
    """The S3 client's own signing credentials, as raw key material for hand-signing."""
    signer = ctx.client("s3")._request_signer._credentials
    assert signer is not None, "the S3 client carries no credentials; the harness must supply credentials"
    frozen = signer.get_frozen_credentials()
    return {"access_key": frozen.access_key, "secret_key": frozen.secret_key, "token": frozen.token}


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _signing_key(secret: str, datestamp: str, region: str) -> bytes:
    key = ("AWS4" + secret).encode()
    for part in (datestamp, region, "s3", "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    return key


def _seed_sign(creds, region, method, host, path, amz_date, extra_headers, payload_sentinel):
    """SigV4-sign the chunked request's headers; x-amz-content-sha256 is the streaming sentinel,
    never the real payload hash. Returns (headers, seed-signature, credential-scope)."""
    datestamp = amz_date[:8]
    headers = {"host": host, "x-amz-content-sha256": payload_sentinel, "x-amz-date": amz_date}
    if creds.get("token"):
        headers["x-amz-security-token"] = creds["token"]
    headers.update(extra_headers)
    names = sorted(headers)
    canonical_headers = "".join(f"{n}:{headers[n].strip()}\n" for n in names)
    signed_headers = ";".join(names)
    canonical_request = "\n".join([
        method, urllib.parse.quote(path, safe="/~"), "",
        canonical_headers, signed_headers, payload_sentinel,
    ])
    scope = f"{datestamp}/{region}/s3/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope, _sha256_hex(canonical_request.encode()),
    ])
    key = _signing_key(creds["secret_key"], datestamp, region)
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={creds['access_key']}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return headers, signature, scope


def _chunk_body_unsigned_trailer(chunks, trailer_name, trailer_value):
    """The aws-chunked body for STREAMING-UNSIGNED-PAYLOAD-TRAILER: plain-sized data chunks, a
    zero-length completion chunk, then the trailer header naming the checksum."""
    out = []
    for chunk in chunks:
        out.append(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
    out.append(b"0\r\n")
    out.append(f"{trailer_name}:{trailer_value}\r\n\r\n".encode())
    return b"".join(out)


def _ssl_context(verify):
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _raw_http(ctx, target, headers, body):
    req = urllib.request.Request(target, method="PUT", data=body)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=60, context=_ssl_context(ctx.http_verify)) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _put_unsigned_trailer(ctx, bucket, key, payload, trailer_name, trailer_value, *, chunk_size=64 * 1024):
    """PUT ``payload`` to ``key`` as an aws-chunked STREAMING-UNSIGNED-PAYLOAD-TRAILER body,
    with ``trailer_name: trailer_value`` as the declared trailing checksum header."""
    target = ctx.s3_object_url(
        f"https://{bucket}.s3.{ctx.region}.amazonaws.com/{urllib.parse.quote(key)}", bucket, key
    )
    parts = urllib.parse.urlsplit(target)
    host, path = parts.netloc, urllib.parse.unquote(parts.path)
    creds = _signing_creds(ctx)
    amz_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    extra = {
        "x-amz-decoded-content-length": str(len(payload)),
        "x-amz-trailer": trailer_name,
    }
    headers, _, _ = _seed_sign(
        creds, ctx.region, "PUT", host, path, amz_date, extra, "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
    )
    chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)] or [b""]
    body = _chunk_body_unsigned_trailer(chunks, trailer_name, trailer_value)
    headers["content-encoding"] = "aws-chunked"
    headers["content-length"] = str(len(body))
    return _raw_http(ctx, target, headers, body)


def _xml_error(body: bytes) -> tuple[str | None, str | None]:
    """The (Code, Message) of an S3 XML error body."""
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return None, None
    return root.findtext("Code"), root.findtext("Message")


def _error_code(fn):
    """The AWS (code, message) ``fn`` raised; an unexpected success raises instead of returning."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
