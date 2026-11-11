"""nodejs22-global-fetch-reads-presigned-object."""
from __future__ import annotations

import io
import json
import time
import zipfile
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodejs22-global-fetch-reads-presigned-object"
GROUP = "nodejs-environment"
SERVICES = ["lambda", "s3"]

_HANDLER = r"""
exports.handler = async (event) => {
  const out = { fetchType: typeof fetch };
  if (typeof fetch !== 'function') return out;
  const res = await fetch(event.url);
  out.status = res.status;
  out.ok = res.ok;
  out.contentType = res.headers.get('content-type');
  out.body = await res.text();
  return out;
};
"""

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A nodejs22.x handler has a global fetch: a GET of a presigned S3 object URL from inside the
    function answers 200 with the object's exact bytes and content type.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-nodejs.html
    """
    s3 = ctx.client("s3")
    lam = ctx.client("lambda")
    bucket = _bucket(ctx, s3)
    key = "fetch/object.txt"
    payload = f"fetched through a presigned URL: {ctx.unique_name('body-')}"
    s3.put_object(Bucket=bucket, Key=key, Body=payload.encode(), ContentType="text/plain")
    ctx.on_cleanup(_teardown(lambda: s3.delete_object(Bucket=bucket, Key=key), "NoSuchBucket"))
    url = _presigned_get(ctx, s3, bucket, key, 600)

    fn = _deploy(ctx, lam, _exec_role(ctx), {"index.js": _HANDLER})
    got = _ok(lam, fn, {"url": url})
    assert got.get("fetchType") == "function", (
        f"typeof fetch in the nodejs22.x handler is {got.get('fetchType')!r}, expected 'function'")
    assert got.get("status") == 200 and got.get("ok") is True, (
        f"fetch of the presigned GetObject URL: status {got.get('status')!r}, ok {got.get('ok')!r}; "
        f"body {str(got.get('body'))[:300]!r}")
    assert got.get("body") == payload, (
        f"fetch returned body {str(got.get('body'))[:300]!r}, expected {payload!r}")
    assert got.get("contentType") == "text/plain", (
        f"fetch returned content-type {got.get('contentType')!r}, expected 'text/plain'")


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


def _bucket(ctx, s3) -> str:
    """A bucket of this check's own, deleted at cleanup."""
    name = ctx.unique_name("sim2real-xsvc-fetch-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=name), "NoSuchBucket"))
    return name


def _exec_role(ctx) -> str:
    """This check's own execution role. It carries no policy, so the function cannot write a log
    group: nothing outlives the function's delete."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _deploy(ctx, lam, role: str, files: dict) -> str:
    """Create a nodejs22.x function from inline ``files``, wait for Active, register its delete."""
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = dict(
        FunctionName=name, Runtime="nodejs22.x", Handler="index.handler", Role=role,
        Code={"ZipFile": _zip(files)}, MemorySize=256, Timeout=20,
        Tags={"sim2real": CHECK},
    )
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = (err["Code"] == "InvalidParameterValueException"
                           and err.get("Message") == _ROLE_NOT_READY)
            if not propagating or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    deadline = time.monotonic() + 90
    while True:
        cfg = lam.get_function_configuration(FunctionName=name)
        assert cfg["State"] != "Failed", f"{name} entered State=Failed: {cfg.get('StateReason')!r}"
        if cfg["State"] == "Active":
            return name
        assert time.monotonic() < deadline, f"{name} not Active within 90s; last {cfg['State']!r}"
        time.sleep(1)


def _ok(lam, name: str, payload) -> dict:
    """RequestResponse invoke returning the decoded result; fails on a FunctionError."""
    resp = lam.invoke(FunctionName=name, InvocationType="RequestResponse",
                      Payload=json.dumps(payload).encode())
    assert resp["StatusCode"] == 200, f"Invoke {name}: StatusCode {resp['StatusCode']!r}, expected 200"
    raw = resp["Payload"].read()
    assert resp.get("FunctionError") is None, (
        f"Invoke {name}: FunctionError={resp.get('FunctionError')!r}, payload {raw[:600]!r}")
    body = json.loads(raw)
    assert isinstance(body, dict), f"Invoke {name}: result {body!r} is not an object"
    return body


def _presigned_get(ctx, s3, bucket: str, key: str, expires_in: int) -> str:
    """A presigned GetObject URL signed for the object's own S3 URL."""
    target = urlsplit(ctx.s3_object_url(f"https://{bucket}.s3.amazonaws.com/{key}", bucket, key))

    def onto_object_url(request, **_) -> None:
        # The signature covers the host and path, so the URL is moved before it is signed.
        request.url = urlsplit(request.url)._replace(
            scheme=target.scheme, netloc=target.netloc, path=target.path
        ).geturl()

    s3.meta.events.register("before-sign.s3.GetObject", onto_object_url)
    try:
        return s3.generate_presigned_url(
            "get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=expires_in
        )
    finally:
        s3.meta.events.unregister("before-sign.s3.GetObject", onto_object_url)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
