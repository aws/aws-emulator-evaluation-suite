"""nodejs-function-sdk-s3-presigner-url-fetches-the-object."""
from __future__ import annotations

import io
import json
import ssl
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodejs-function-sdk-s3-presigner-url-fetches-the-object"
GROUP = "data-plane"
SERVICES = ["lambda", "s3"]

_RUNTIME = "nodejs22.x"
_SOURCE_FILE = "index.mjs"
_HANDLER = """\
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

export const handler = async (event) => {
  const client = new S3Client({});
  const url = await getSignedUrl(client, new GetObjectCommand({ Bucket: event.bucket, Key: event.key }),
                                 { expiresIn: 300 });
  return { url };
};
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A presigned GET URL a Node.js function builds with @aws-sdk/s3-request-presigner serves the
    object's bytes to a caller holding no credentials.

    Reference: https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/Package/-aws-sdk-s3-request-presigner/
    """
    s3 = ctx.client("s3")
    part = _partition(ctx)
    bucket = _bucket(ctx)
    body = b"presigned-by-the-function-" + ctx.unique_name("").encode()
    s3.put_object(Bucket=bucket, Key="shared.txt", Body=body)
    role = _execution_role(ctx, [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:{part}:s3:::{bucket}/*"},
    ])
    fn = _function(ctx, role["arn"], _HANDLER)

    out = _invoke_granted(ctx, fn["name"], {"bucket": bucket, "key": "shared.txt"})
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(out["url"]).query)
    assert query.get("X-Amz-Expires") == ["300"], f"presigned URL lifetime {query.get('X-Amz-Expires')!r}"
    assert query.get("X-Amz-Signature"), "the presigned URL carries no signature"
    # The URL is the one the function's SDK signed against its own S3 endpoint.
    url = ctx.endpoint_url(out["url"])
    verify = ctx.http_verify
    # The fetch always verifies: http_verify is the emulator's CA bundle path for a TLS emulator,
    # else the default trust store applies (an unverified HTTPS context is never used).
    tls_context = ssl.create_default_context(cafile=verify) if isinstance(verify, str) else None

    def fetch():
        # The URL is signed by the role, so an AccessDenied 403 is its grant still propagating.
        try:
            with urllib.request.urlopen(url, timeout=60, context=tls_context) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            code = _error_code(exc.read())
            if exc.code == 403 and code == "AccessDenied":
                return 403, b""
            raise AssertionError(f"the function's presigned URL did not serve the object: "
                                 f"HTTP {exc.code} {code}") from exc
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
            raise AssertionError(f"the function's presigned URL did not serve the object: "
                                 f"{type(exc).__name__}: {exc}") from exc

    status, got = _poll(fetch, lambda r: r[0] != 403, timeout_s=90, interval_s=5,
                        what="the presigned URL's signer is granted s3:GetObject")
    assert status == 200, f"presigned GET answered {status}"
    assert got == body, f"presigned GET returned {len(got)} bytes, expected {len(body)}"


def _error_code(body: bytes):
    """The ``Code`` of an S3 XML error body, or None when the body carries none."""
    try:
        return ET.fromstring(body).findtext("Code")
    except ET.ParseError:
        return None


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll(probe, done, *, timeout_s, interval_s, what):
    """``probe()`` until ``done(result)``; raises naming ``what`` and the last result on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(_SOURCE_FILE, textwrap.dedent(code))
    return buf.getvalue()


def _partition(ctx) -> str:
    """The caller's partition, read off its own ARN, never a literal."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], f"unparseable caller ARN {arn!r}"
    return parts[1]


def _execution_role(ctx, statements) -> dict:
    """A Lambda execution role holding exactly ``statements`` and no logs: grant, so the function
    never creates a log group that could outlive the check."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
        ctx.on_cleanup(_teardown(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
            "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"], "id": role["RoleId"]}


def _function(ctx, role_arn, code, *, timeout=60) -> dict:
    """A function from ``code``, created through the role-propagation window and Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": _RUNTIME, "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code)}, "Timeout": timeout,
              "MemorySize": 256, "Tags": {"sim2real": CHECK}}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")):
                return None
            raise

    out = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3,
                what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"),
                 timeout_s=90, interval_s=1, what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return {"name": name, "arn": out["FunctionArn"]}


def _invoke(ctx, fn, event=None) -> tuple:
    """(FunctionError or None, decoded payload) of one RequestResponse invoke of ``event``."""
    resp = ctx.client("lambda").invoke(FunctionName=fn, InvocationType="RequestResponse",
                                       Payload=json.dumps(event or {}).encode())
    raw = resp["Payload"].read()
    return resp.get("FunctionError"), (json.loads(raw) if raw else None)


def _denied(result) -> bool:
    """Whether an invoke's payload shows a refusal the role's still-propagating grants explain."""
    text = json.dumps(result[1])
    return "AccessDenied" in text or '"status": 403' in text or '"code": "403"' in text


def _invoke_granted(ctx, fn, event) -> dict:
    """The payload of ``fn`` once the role's grants are effective; any other failure raises."""
    err, out = _poll(lambda: _invoke(ctx, fn, event), lambda r: not _denied(r),
                     timeout_s=90, interval_s=5, what="the role's s3 grants are effective")
    assert err is None, f"the function failed: {err!r} {out!r}"
    return out


def _empty_and_delete(s3, name):
    """Delete every object of ``name``, then the bucket."""

    def undo() -> None:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    return undo


def _bucket(ctx) -> str:
    """A bucket of ours, emptied and deleted at cleanup."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-xsvc-b-")
    # us-east-1 is not a region literal pin: CreateBucket rejects an explicit
    # LocationConstraint for that region specifically, so it is omitted only there.
    kw = {} if ctx.region == "us-east-1" else {
        "CreateBucketConfiguration": {"LocationConstraint": ctx.region}}
    s3.create_bucket(Bucket=name, **kw)
    ctx.on_cleanup(_teardown(_empty_and_delete(s3, name), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
