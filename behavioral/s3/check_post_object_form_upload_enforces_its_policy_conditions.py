"""post-object-form-upload-enforces-its-policy-conditions."""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import ssl
import urllib.error
import urllib.request
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "post-object-form-upload-enforces-its-policy-conditions"
GROUP = "auth_enforcement"
SERVICES = ["s3"]

_PREFIX = "uploads/"
_MAX_BYTES = 4096


@tags(
    "axis:rejection",
    "cap:c2",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A POST Object form upload is admitted or refused by its signed policy document: a key outside
    the `starts-with` prefix and a file over `content-length-range` are refused and not stored,
    while the same form with a conforming key and size succeeds.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    post_url = _bucket_post_url(ctx, s3, bucket)
    form = _signed_post_form(ctx, bucket, prefix=_PREFIX, max_bytes=_MAX_BYTES)

    # --- Beat 1: positive control. Without this leg, "POST is refused" cannot be told apart from
    # "POST Object is not implemented and every POST is refused".
    good_key = f"{_PREFIX}accepted-{uuid.uuid4().hex}.txt"
    good_body = b"post-object-conforming-upload"
    status, body = _post(ctx, post_url, dict(form, key=good_key), good_body)
    assert status == 201, (
        f"the conforming POST Object was answered {status} with {body[:200]!r}; a POST whose form "
        "satisfies every policy condition and carries success_action_status=201 must be accepted "
        "with 201"
    )
    assert f"<Key>{good_key}</Key>".encode() in body, (
        f"the 201 POST response body did not name the uploaded key {good_key!r}: {body[:300]!r}"
    )
    # The terminal read is a different operation (GetObject) against the stored object, not the
    # POST response.
    stored = s3.get_object(Bucket=bucket, Key=good_key)["Body"].read()
    assert stored == good_body, (
        f"GetObject returned {stored!r} for the POST-uploaded key {good_key!r}; the form part "
        f"carried {good_body!r}"
    )

    # --- Beat 2: break exactly ONE thing — the key leaves the prefix the policy pins. Same policy,
    # same signature, same body, same size.
    bad_key = f"escaped/{uuid.uuid4().hex}.txt"
    status, body = _post(ctx, post_url, dict(form, key=bad_key), good_body)
    assert status == 403, (
        f"POSTing key {bad_key!r} against a policy that pins ['starts-with', '$key', "
        f"{_PREFIX!r}] was answered {status} with {body[:200]!r}; expected 403 — the policy "
        "condition is not being evaluated, so any holder of the form can write anywhere in the "
        "bucket"
    )
    assert b"<Code>AccessDenied</Code>" in body, (
        f"the refused POST returned no AccessDenied code: {body[:300]!r}"
    )
    # Effect absent, by an independent read.
    assert _error_code(lambda: s3.head_object(Bucket=bucket, Key=bad_key)) == "404", (
        f"the key {bad_key!r} exists after a POST that was refused with 403 — the refusal did not "
        "prevent the write"
    )

    # --- Beat 3: break exactly one OTHER thing — the size leaves content-length-range.
    oversize_key = f"{_PREFIX}oversize-{uuid.uuid4().hex}.txt"
    oversize_body = b"x" * (_MAX_BYTES + 1)
    status, body = _post(ctx, post_url, dict(form, key=oversize_key), oversize_body)
    assert status == 400, (
        f"POSTing {len(oversize_body)} bytes against a policy whose content-length-range maximum "
        f"is {_MAX_BYTES} was answered {status} with {body[:200]!r}; expected 400"
    )
    assert b"<Code>EntityTooLarge</Code>" in body, (
        f"the oversize POST returned no EntityTooLarge code: {body[:300]!r}"
    )
    assert _error_code(lambda: s3.head_object(Bucket=bucket, Key=oversize_key)) == "404", (
        f"the key {oversize_key!r} exists after a POST refused for exceeding "
        f"content-length-range={_MAX_BYTES}"
    )

    # --- Beat 4: restore. The identical form, with a conforming key and size, succeeds again — so
    # the two refusals were about the two broken conditions and not about the signature having
    # been spent, the policy having expired, or the endpoint having stopped accepting POSTs.
    restored_key = f"{_PREFIX}restored-{uuid.uuid4().hex}.txt"
    restored_body = b"post-object-after-two-refusals"
    status, body = _post(ctx, post_url, dict(form, key=restored_key), restored_body)
    assert status == 201, (
        f"the restored conforming POST was answered {status} with {body[:200]!r}; the same signed "
        "policy accepted an upload before the two refusals and must accept one after them"
    )
    assert s3.get_object(Bucket=bucket, Key=restored_key)["Body"].read() == restored_body, (
        f"GetObject did not return {restored_body!r} for {restored_key!r} after the restore leg"
    )

    # The bucket now holds exactly the two accepted keys and neither refused one. ListObjectsV2 is
    # a third operation, so this is independent of both the POST responses and the HEADs above.
    listed = {
        o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    }
    assert listed == {good_key, restored_key}, (
        f"the bucket lists {sorted(listed)}; expected exactly the two accepted keys "
        f"{sorted([good_key, restored_key])} — a refused POST left an object behind"
    )


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it. TEARDOWN ONLY —
    never on an assertion path."""
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


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named, tagged bucket; register empty+delete teardown; return its name."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"},
                            {"Key": "sim2real:check", "Value": CHECK}]},
    )
    return name


def _error_code(fn) -> str:
    """The botocore Error.Code (or HTTP status for a code-less S3 HEAD) of fn(); RAISES if fn
    succeeds."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code:
            return code
        return str(exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", "unknown"))
    raise AssertionError("the call was expected to fail and it succeeded")


def _frozen_credentials(ctx):
    """ctx's own signing credentials, frozen. Nothing ambient is resolved here."""
    signer = ctx.client("s3")._request_signer
    creds = signer._credentials
    assert creds is not None, (
        "ctx.client('s3') carries no credentials, so no POST policy can be signed"
    )
    return creds.get_frozen_credentials()


def _bucket_post_url(ctx, s3, bucket: str) -> str:
    """The POST Object target (bucket root, trailing slash): a presigned PutObject URL with its
    query and probe key stripped, which suits either addressing style the target uses."""
    probe_key = "post-object-endpoint-probe"
    presigned = s3.generate_presigned_url(
        "put_object", Params={"Bucket": bucket, "Key": probe_key}, ExpiresIn=60
    )
    base = presigned.split("?", 1)[0]
    assert base.endswith("/" + probe_key), (
        f"cannot derive the bucket URL: the presigned PutObject URL {base!r} does not end in "
        f"/{probe_key}"
    )
    return base[: -len(probe_key)]


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signed_post_form(ctx, bucket: str, *, prefix: str, max_bytes: int) -> dict[str, str]:
    """Build and SigV4-sign a POST Object policy from the live clock, returning every form field
    except `key`/`file`. Each field has a matching policy condition: POST Object refuses a form
    carrying any field the policy does not cover."""
    creds = _frozen_credentials(ctx)
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    expiration = (now + datetime.timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
    credential = f"{creds.access_key}/{datestamp}/{ctx.region}/s3/aws4_request"

    conditions: list = [
        {"bucket": bucket},
        ["starts-with", "$key", prefix],
        {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
        {"x-amz-credential": credential},
        {"x-amz-date": amz_date},
        {"success_action_status": "201"},
        ["content-length-range", 1, max_bytes],
    ]
    if creds.token:
        conditions.append({"x-amz-security-token": creds.token})

    policy = base64.b64encode(
        json.dumps({"expiration": expiration, "conditions": conditions}).encode("utf-8")
    ).decode("ascii")

    signing_key = _sign(
        _sign(_sign(_sign(f"AWS4{creds.secret_key}".encode("utf-8"), datestamp), ctx.region), "s3"),
        "aws4_request",
    )
    signature = hmac.new(signing_key, policy.encode("utf-8"), hashlib.sha256).hexdigest()

    form = {
        "x-amz-algorithm": "AWS4-HMAC-SHA256",
        "x-amz-credential": credential,
        "x-amz-date": amz_date,
        "success_action_status": "201",
        "policy": policy,
        "x-amz-signature": signature,
    }
    if creds.token:
        form["x-amz-security-token"] = creds.token
    return form


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


def _post(ctx, url: str, fields: dict[str, str], file_bytes: bytes) -> tuple[int, bytes]:
    """POST a `multipart/form-data` body (`key` first, `file` last, as S3 requires); return (status,
    body). One 307 is followed, as any client does: the derived URL can land on S3's global host,
    which redirects out-of-region buckets to their regional host before evaluating the policy."""

    def _once(target: str) -> tuple[int, bytes, str | None]:
        boundary = f"----sim2real{uuid.uuid4().hex}"
        parts: list[bytes] = []
        ordered = ["key"] + [k for k in fields if k != "key"]
        for name in ordered:
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{fields[name]}\r\n".encode("utf-8")
            )
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="payload.bin"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode(
                "utf-8"
            )
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
