"""function-handler-http-client-fetches-a-presigned-url."""
from __future__ import annotations

import base64
import io
import json
import textwrap
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "function-handler-http-client-fetches-a-presigned-url"
GROUP = "data-plane"
SERVICES = ['lambda', 's3']

_RUNTIME = "python3.12"
_SOURCE_FILE = "index.py"
_HANDLER = """\
import base64
import http.client
import urllib.parse


def handler(event, context):
    url = urllib.parse.urlsplit(event["url"])
    target = url.path + ("?" + url.query if url.query else "")
    try:
        # The URL keeps its own scheme: https on AWS, plain http on a plaintext target.
        if url.scheme == "https":
            conn = http.client.HTTPSConnection(url.hostname, url.port or 443, timeout=30)
        else:
            conn = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=30)
        try:
            conn.request("GET", target)
            resp = conn.getresponse()
            body = resp.read()
        finally:
            conn.close()
    except Exception as exc:
        return {"error": type(exc).__name__, "message": str(exc), "scheme": url.scheme}
    return {"status": resp.status, "bodyB64": base64.b64encode(body).decode()}
"""



@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A Python function's http.client.HTTPSConnection GET of a presigned S3 URL's host and
    path, made with no credentials of its own, answers 200 with the object's exact bytes.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/ShareObjectPreSignedURL.html
    """
    # Virtual-hosted style signs the bucket's Regional host: the global one answers a fresh
    # bucket with 307 TemporaryRedirect, which this client does not follow.
    s3 = ctx.client("s3", config=Config(s3={"addressing_style": "virtual"}))
    bucket = _bucket(ctx)
    body = bytes(range(256)) * 4 + ctx.unique_name("").encode()
    s3.put_object(Bucket=bucket, Key="fetched.bin", Body=body)
    url = s3.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": "fetched.bin"},
                                    ExpiresIn=300)
    role = _execution_role(ctx, [])
    fn = _function(ctx, role["arn"], _HANDLER)
    out = _invoke_ok(ctx, fn["name"], {"url": url})
    assert "error" not in out, f"http.client.HTTPSConnection GET failed in the function: {out!r}"
    assert out["status"] == 200, f"http.client.HTTPSConnection GET answered status {out['status']!r}, expected 200: {out!r}"
    got = base64.b64decode(out["bodyB64"])
    assert got == body, f"http.client.HTTPSConnection GET returned {len(got)} bytes that differ from the {len(body)} stored"



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


def _invoke_ok(ctx, fn, event=None) -> dict:
    """The payload of one invoke that must not report a FunctionError."""
    err, out = _invoke(ctx, fn, event)
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
