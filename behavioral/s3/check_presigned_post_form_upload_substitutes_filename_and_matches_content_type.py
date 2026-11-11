"""presigned-post-form-upload-substitutes-filename-and-matches-content-type."""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "presigned-post-form-upload-substitutes-filename-and-matches-content-type"
GROUP = "auth_enforcement"
SERVICES = ["s3"]


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; TEARDOWN ONLY."""
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
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    """Create a uniquely-named, tagged bucket; register empty+delete teardown; return its name."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    # us-east-1 rejects an explicit LocationConstraint naming itself; every other region needs one.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"},
                            {"Key": "sim2real:check", "Value": CHECK}]},
    )
    return name


def _https_context(verify) -> ssl.SSLContext:
    """The TLS context http.client builds by default, verifying with ``ctx.http_verify``."""
    if verify is False:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(cafile=verify if isinstance(verify, str) and verify else None)
    context.set_alpn_protocols(["http/1.1"])
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


def _post(ctx, url: str, fields: dict[str, str], filename: str, file_bytes: bytes,
          file_content_type: str | None) -> tuple[int, bytes]:
    """POST a `multipart/form-data` body with `key` first and `file` last; return (status, body).

    S3 stops reading fields at `file`. One 307 to the regional host is followed, as SDKs do.
    """

    def _once(target: str) -> tuple[int, bytes, str | None]:
        boundary = f"----sim2real{uuid.uuid4().hex}"
        parts: list[bytes] = []
        ordered = ["key"] + [k for k in fields if k != "key"]
        for name in ordered:
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{fields[name]}\r\n".encode("utf-8")
            )
        ct_line = f"\r\nContent-Type: {file_content_type}" if file_content_type else ""
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="{filename}"{ct_line}\r\n\r\n'.encode("utf-8")
        )
        parts.append(file_bytes)
        parts.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))
        body = b"".join(parts)

        req = urllib.request.Request(target, method="POST", data=body)
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        req.add_header("Content-Length", str(len(body)))
        try:
            with urllib.request.urlopen(
                req, timeout=60, context=_https_context(ctx.http_verify)
            ) as resp:
                return resp.status, resp.read(), None
        except urllib.error.HTTPError as exc:
            location = exc.headers.get("Location") if exc.code == 307 else None
            return exc.code, exc.read(), location

    status, body, location = _once(url)
    if status == 307 and location:
        status, body, _ = _once(ctx.endpoint_url(location))
    return status, body


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c7",
    "concern:data-plane",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A presigned POST form upload substitutes `${filename}` into the key server-side.

    The stored object's bytes and Content-Type match the form, and no literal-token key is written.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    prefix = "uploads/"
    content_type = "text/plain"

    presigned = s3.generate_presigned_post(
        Bucket=bucket,
        Key=prefix + "${filename}",
        Fields={"Content-Type": content_type, "success_action_status": "201"},
        Conditions=[
            {"success_action_status": "201"},
            ["starts-with", "$key", prefix],
            ["eq", "$Content-Type", content_type],
        ],
        ExpiresIn=120,
    )
    url, fields = presigned["url"], presigned["fields"]
    assert fields["key"] == prefix + "${filename}", (
        f"generate_presigned_post returned key field {fields['key']!r}; expected the literal "
        f"token {prefix + '${filename}'!r} for the client to substitute nothing itself"
    )

    uploaded_name = f"report-{uuid.uuid4().hex}.txt"
    body_bytes = b"quarterly totals: 42, 17, 9"
    status, resp_body = _post(ctx, url, fields, uploaded_name, body_bytes, content_type)
    assert status == 201, (
        f"the POST was answered {status} with {resp_body[:300]!r}; a form satisfying every "
        "policy condition and carrying success_action_status=201 must be accepted with 201"
    )

    expected_key = prefix + uploaded_name
    assert f"<Key>{expected_key}</Key>".encode() in resp_body, (
        f"the 201 PostResponse body did not substitute {uploaded_name!r} into the key: "
        f"{resp_body[:400]!r}; expected key {expected_key!r}"
    )
    assert f"<Bucket>{bucket}</Bucket>".encode() in resp_body, (
        f"the 201 PostResponse body did not name bucket {bucket!r}: {resp_body[:400]!r}"
    )
    assert b"<ETag>" in resp_body, (
        f"the 201 PostResponse body carried no <ETag>: {resp_body[:400]!r}"
    )

    # HeadObject proves the stored bytes and content-type, not the POST response's own claim.
    head = s3.head_object(Bucket=bucket, Key=expected_key)
    assert head["ContentLength"] == len(body_bytes), (
        f"HeadObject reports ContentLength={head['ContentLength']!r}; the form carried "
        f"{len(body_bytes)} bytes"
    )
    assert head["ContentType"] == content_type, (
        f"HeadObject reports ContentType={head['ContentType']!r}; the form's Content-Type field "
        f"carried {content_type!r}"
    )
    stored = s3.get_object(Bucket=bucket, Key=expected_key)["Body"].read()
    assert stored == body_bytes, (
        f"GetObject returned {stored!r} for {expected_key!r}; the form part carried {body_bytes!r}"
    )

    # The literal-token key was never written: only the substituted key exists.
    literal_key = prefix + "${filename}"
    assert _error_code(lambda: s3.head_object(Bucket=bucket, Key=literal_key)) == "404", (
        f"a key named after the unsubstituted literal token {literal_key!r} exists — "
        "${filename} substitution did not happen, or happened to the wrong key"
    )


def _error_code(fn) -> str:
    """The Error.Code of fn(); raises AssertionError if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
