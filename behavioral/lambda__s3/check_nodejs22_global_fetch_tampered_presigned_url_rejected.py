"""nodejs22-global-fetch-tampered-presigned-url-rejected."""
from __future__ import annotations

import io
import json
import re
import time
import zipfile
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodejs22-global-fetch-tampered-presigned-url-rejected"
GROUP = "nodejs-environment"
SERVICES = ["lambda", "s3"]

_HANDLER = r"""
const pick = (xml, tag) => {
  const m = new RegExp('<' + tag + '>([^<]*)</' + tag + '>').exec(xml);
  return m ? m[1] : null;
};
exports.handler = async (event) => {
  const out = { fetchType: typeof fetch };
  if (typeof fetch !== 'function') return out;
  const good = await fetch(event.good);
  out.good = { status: good.status, body: await good.text() };
  const bad = await fetch(event.tampered);
  const xml = await bad.text();
  out.tampered = { status: bad.status, code: pick(xml, 'Code'), message: pick(xml, 'Message') };
  return out;
};
"""

_SIGNATURE_MISMATCH = ("The request signature we calculated does not match the signature you "
                       "provided. Check your key and signing method.")

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A nodejs22.x handler's fetch of a presigned S3 URL whose signature was altered is refused 403
    SignatureDoesNotMatch with S3's exact message, while the untouched URL still reads the object.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html
    """
    s3 = ctx.client("s3")
    lam = ctx.client("lambda")
    bucket = _bucket(ctx, s3)
    key = "fetch/object.txt"
    payload = f"fetched through a presigned URL: {ctx.unique_name('body-')}"
    s3.put_object(Bucket=bucket, Key=key, Body=payload.encode(), ContentType="text/plain")
    ctx.on_cleanup(_teardown(lambda: s3.delete_object(Bucket=bucket, Key=key), "NoSuchBucket"))
    url = _presigned_get(ctx, s3, bucket, key, 600)
    tampered = _tamper(url)

    fn = _deploy(ctx, lam, _exec_role(ctx), {"index.js": _HANDLER})
    got = _ok(lam, fn, {"good": url, "tampered": tampered})
    assert got.get("fetchType") == "function", (
        f"typeof fetch in the nodejs22.x handler is {got.get('fetchType')!r}, expected 'function'")
    good = got.get("good") or {}
    assert good.get("status") == 200 and good.get("body") == payload, (
        f"control: the untouched presigned URL answered {good.get('status')!r} with body "
        f"{str(good.get('body'))[:300]!r}, expected 200 and {payload!r}")
    bad = got.get("tampered") or {}
    assert bad.get("status") == 403, (
        f"the altered signature answered HTTP {bad.get('status')!r}, expected 403 "
        f"(code {bad.get('code')!r})")
    assert bad.get("code") == "SignatureDoesNotMatch", (
        f"the altered signature answered code {bad.get('code')!r}, expected 'SignatureDoesNotMatch'")
    assert bad.get("message") == _SIGNATURE_MISMATCH, (
        f"the altered signature answered message {bad.get('message')!r}, expected {_SIGNATURE_MISMATCH!r}")


def _tamper(url: str) -> str:
    """``url`` with the first character of its signature swapped for a different digit."""
    match = re.search(r"[?&](?:X-Amz-Signature|Signature)=([0-9A-Za-z])", url)
    assert match, f"the presigned URL carries no signature (query keys {_query_keys(url)!r})"
    start = match.start(1)
    # A digit differs from the original in value, not only in case: SigV4 is lowercase hex.
    char = "1" if url[start] == "0" else "0"
    return url[:start] + char + url[start + 1:]


def _query_keys(url: str) -> list:
    return [pair.split("=", 1)[0] for pair in url.split("?", 1)[-1].split("&")]


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
