"""presigned-post-expired-policy-rejected-and-writes-nothing."""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "presigned-post-expired-policy-rejected-and-writes-nothing"
GROUP = "auth_enforcement"
SERVICES = ["s3"]

_PREFIX = "uploads/"
_MAX_BYTES = 16


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


def _error_code(fn) -> str:
    """The Error.Code of fn()."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _error_fields(body: bytes) -> tuple[str | None, str | None]:
    """Parse an S3 `<Error>` XML body and return its (Code, Message)."""
    root = ET.fromstring(body)
    return root.findtext("Code"), root.findtext("Message")


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


def _post(ctx, url: str, fields: dict[str, str], filename: str, file_bytes: bytes) -> tuple[int, bytes]:
    """POST a `multipart/form-data` body; return (status, body). 4xx/5xx are answers, not errors.

    A single HTTP 307 is followed transparently: the bucket's global virtual-hosted host (what
    `generate_presigned_post` returns outside us-east-1) redirects to the bucket's regional host
    before evaluating the policy, and every AWS SDK follows that 307, so this is transport.
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
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="{filename}"\r\n\r\n'.encode("utf-8")
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
    "axis:rejection",
    "cap:c2",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A presigned POST whose policy expiration is in the past is refused with 403 AccessDenied 'Invalid
    according to Policy: Policy expired.' and writes nothing, while the same form with an unexpired
    policy uploads with 201 and stores its bytes."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    conditions = [
        {"success_action_status": "201"},
        ["starts-with", "$key", _PREFIX],
        ["content-length-range", 1, _MAX_BYTES],
    ]

    presigned = s3.generate_presigned_post(
        Bucket=bucket,
        Key=_PREFIX + "${filename}",
        Fields={"success_action_status": "201"},
        Conditions=conditions,
        ExpiresIn=600,
    )

    # --- Beat 1: positive control. Without it, "the expired policy is refused" cannot be told
    # apart from "POST Object is not implemented and every POST is refused".
    good_name = f"good-{uuid.uuid4().hex}.txt"
    good_body = b"ok"
    status, resp_body = _post(ctx, presigned["url"], presigned["fields"], good_name, good_body)
    assert status == 201, (
        f"the conforming POST was answered {status} with {resp_body[:300]!r}; expected 201"
    )
    good_key = _PREFIX + good_name
    stored = s3.get_object(Bucket=bucket, Key=good_key)["Body"].read()
    assert stored == good_body, (
        f"GetObject returned {stored!r} for the POST-uploaded key {good_key!r}; expected "
        f"{good_body!r}"
    )

    # --- Beat 2: the same policy signed with an expiration 60 s in the past. Bucket, conditions
    # and signing path match Beat 1, isolating the refusal to the policy's clock.
    expired = s3.generate_presigned_post(
        Bucket=bucket,
        Key=_PREFIX + "${filename}",
        Fields={"success_action_status": "201"},
        Conditions=conditions,
        ExpiresIn=-60,
    )
    expired_name = f"expired-{uuid.uuid4().hex}.txt"
    status, resp_body = _post(ctx, expired["url"], expired["fields"], expired_name, b"ok")
    assert status == 403, (
        f"POSTing against a policy whose expiration already elapsed was answered {status} with "
        f"{resp_body[:300]!r}; expected 403"
    )
    code, message = _error_fields(resp_body)
    assert code == "AccessDenied", (
        f"the expired-policy POST returned code {code!r}; expected 'AccessDenied': {resp_body[:400]!r}"
    )
    expected_msg = "Invalid according to Policy: Policy expired."
    assert message == expected_msg, (
        f"the expired-policy POST returned message {message!r}; expected {expected_msg!r}"
    )
    expired_key = _PREFIX + expired_name
    assert _error_code(lambda: s3.head_object(Bucket=bucket, Key=expired_key)) == "404", (
        f"the key {expired_key!r} exists after a POST refused for an expired policy"
    )

    # --- Beat 3: an independent listing shows exactly the accepted key.
    listed = {o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])}
    assert listed == {good_key}, (
        f"the bucket lists {sorted(listed)}; expected exactly {[good_key]} — the refused POST "
        "left an object behind"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
