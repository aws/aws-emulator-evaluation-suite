"""s3-chunked-upload-trailer-checksum-stores-object-and-checksum."""
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

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-chunked-upload-trailer-checksum-stores-object-and-checksum"
GROUP = "chunked-upload"
SERVICES = ["s3"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An aws-chunked PUT signed STREAMING-UNSIGNED-PAYLOAD-TRAILER with an x-amz-checksum-crc32
    trailer stores the object bytes and records that trailer's checksum as object metadata.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "chunked/trailer-ok.bin"
    payload = b"aws-chunked-trailer-checksum-payload-" * 60
    crc32 = base64.b64encode(binascii.crc32(payload).to_bytes(4, "big")).decode()

    status, body = _put_unsigned_trailer(ctx, bucket, key, payload, "x-amz-checksum-crc32", crc32)
    assert status == 200, f"a valid aws-chunked trailer-checksum PUT returned {status}: {body[:300]!r}"

    head = s3.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    assert head.get("ChecksumCRC32") == crc32, (
        f"HeadObject reports ChecksumCRC32={head.get('ChecksumCRC32')!r}, expected {crc32!r}"
    )
    got = s3.get_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    got_body = got["Body"].read()
    assert got_body == payload, f"stored body is {got_body!r}, expected {payload!r}"
    assert got.get("ChecksumCRC32") == crc32, (
        f"GetObject reports ChecksumCRC32={got.get('ChecksumCRC32')!r}, expected {crc32!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
