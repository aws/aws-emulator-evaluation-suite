"""deep-apigatewayv2-2-enforce-payload-10mib-limit-413-not-delivered."""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-apigatewayv2-2-enforce-payload-10mib-limit-413-not-delivered"

GROUP = "enforcement"

SERVICES = ["apigatewayv2"]

#: HTTP API maximum payload size ("10 MB", not adjustable); exactly 10 * 1024 * 1024 bytes is
#: delivered and one byte more is refused, so the unit is MiB.
_LIMIT = 10 * 1024 * 1024

#: Statuses the edge sometimes answers an over-limit body with instead of the gateway's 413
#: (an HTML 502 page, a 503 envelope, or 404 from a node without the new deployment yet); these
#: are retried, while any other status, above all a 2xx, fails at once.
_EDGE_TRANSIENT = frozenset({404, 502, 503})
_VERDICT_ATTEMPTS = 8


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """The HTTP API 10 MiB payload limit is enforced at the exact byte before the integration: a
    10 MiB + 1 body gets 413 and never reaches S3, exactly 10 MiB lands byte-for-byte, and a second
    over-limit body does not overwrite it.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-quotas.html
    """
    # PUT /upload proxies to an S3 presigned URL, so whatever the gateway forwards is readable.
    # The URL names the regional virtual host: the global s3.amazonaws.com host answers a
    # brand-new bucket with 307 TemporaryRedirect, which the proxy does not follow.
    s3 = ctx.client(
        "s3", config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"})
    )
    bucket = ctx.unique_name("sim2real-behav-413-")
    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":  # us-east-1 rejects an explicit constraint
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv()})

    def presign(key):
        # The URL is signed for the object's own S3 URL, so the host is moved before signing.
        target = urllib.parse.urlsplit(ctx.s3_object_url(
            f"https://{bucket}.s3.{ctx.region}.amazonaws.com/{key}", bucket, key
        ))

        def onto_object_url(request, **_):
            request.url = urllib.parse.urlsplit(request.url)._replace(
                scheme=target.scheme, netloc=target.netloc, path=target.path
            ).geturl()

        s3.meta.events.register("before-sign.s3.PutObject", onto_object_url)
        try:
            return s3.generate_presigned_url(
                "put_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=3600
            )
        finally:
            s3.meta.events.unregister("before-sign.s3.PutObject", onto_object_url)

    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_name(ctx, "httpapi-413"), ProtocolType="HTTP", Tags=_resource_tags()
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    for path, key in (("/warm", "warm"), ("/upload", "payload")):
        integration_id = agw.create_integration(
            ApiId=api_id,
            IntegrationType="HTTP_PROXY",
            IntegrationMethod="PUT",
            IntegrationUri=presign(key),
            PayloadFormatVersion="1.0",
        )["IntegrationId"]
        agw.create_route(ApiId=api_id, RouteKey=f"PUT {path}", Target=f"integrations/{integration_id}")
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )
    warm_url = _invoke_url(ctx, api["ApiEndpoint"], "$default", "/warm")
    upload_url = _invoke_url(ctx, api["ApiEndpoint"], "$default", "/upload")

    # Positive control: the proxy delivers a small body to S3 through the sibling route.
    for _ in range(3):  # three successes: a new deployment reaches the edge node by node
        _poll_http(
            warm_url,
            method="PUT",
            body=b"warm",
            accept=lambda s: s == 200,
            description="PUT /warm proxying a small body to S3",
        )
    warm = s3.head_object(Bucket=bucket, Key="warm")
    assert warm["ContentLength"] == 4, (
        f"precondition: PUT /warm must land its 4-byte body in S3, HeadObject says "
        f"{warm['ContentLength']!r}"
    )

    # One byte over the limit: refused at the edge, nothing lands.
    over = b"b" * (_LIMIT + 1)
    status, text, seen = _put_until_verdict(upload_url, over)
    assert status == 413, (
        f"a {_LIMIT + 1}-byte body (10 MiB + 1) must be refused with 413, got {status}: "
        f"{text[:200]!r} (attempts: {seen!r})"
    )
    assert _json_or_none(text) == {"message": "Request Entity Too Large"}, (
        f'the refusal must be the gateway\'s {{"message":"Request Entity Too Large"}} envelope, '
        f"got {text[:200]!r}"
    )
    code = _error_code(lambda: s3.head_object(Bucket=bucket, Key="payload"))
    assert code == "404", (
        f"an over-limit body refused with 413 must never reach the integration, but the "
        f"destination key's HeadObject returned {code!r} instead of 404"
    )

    # Exactly the limit: served, and the destination holds every byte.
    exact = b"a" * _LIMIT
    status, _, text = _http("PUT", upload_url, body=exact, timeout_s=120)
    assert status == 200, (
        f"a body of exactly {_LIMIT} bytes (10 MiB) is within the limit and must be proxied, got "
        f"{status}: {text[:200]!r}"
    )
    landed = s3.head_object(Bucket=bucket, Key="payload")
    assert landed["ContentLength"] == _LIMIT, (
        f"the 10 MiB body must land byte-for-byte; HeadObject ContentLength is "
        f"{landed['ContentLength']!r}, expected {_LIMIT}"
    )
    want_etag = hashlib.md5(exact).hexdigest()
    assert landed["ETag"].strip('"') == want_etag, (
        f"the landed object's ETag {landed['ETag']!r} is not the MD5 {want_etag!r} of the body sent"
    )

    # Over the limit again: refused, and the delivered object is untouched.
    status, text, seen = _put_until_verdict(upload_url, over)
    assert status == 413, (
        f"a second {_LIMIT + 1}-byte body must be refused with 413 as well, got {status}: "
        f"{text[:200]!r} (attempts: {seen!r})"
    )
    after = s3.head_object(Bucket=bucket, Key="payload")
    assert (after["ContentLength"], after["ETag"]) == (landed["ContentLength"], landed["ETag"]), (
        f"a refused over-limit body overwrote the destination: now {after['ContentLength']!r} "
        f"bytes / {after['ETag']!r}, was {landed['ContentLength']!r} / {landed['ETag']!r}"
    )


def _put_until_verdict(url, body):
    """PUT body until the answer is not an edge transient; return (status, text, attempts).
    RAISES if no verdict arrives within _VERDICT_ATTEMPTS."""
    seen = []
    for _ in range(_VERDICT_ATTEMPTS):
        try:
            status, _, text = _http("PUT", url, body=body, timeout_s=120)
        except OSError as exc:  # the edge may reset a connection still uploading a refused body
            status, text = None, f"connection error: {exc}"
        seen.append(status)
        if status is not None and status not in _EDGE_TRANSIENT:
            return status, text, seen
        time.sleep(2.0)
    raise AssertionError(
        f"no gateway verdict for a {len(body)}-byte PUT to {url} in {_VERDICT_ATTEMPTS} attempts; "
        f"statuses {seen!r}, last body {text[:200]!r}"
    )


def _error_code(fn):
    """The AWS error code fn raises. RAISES if fn succeeds - success is not a code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"expected the call to fail, it succeeded: {result!r}")


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
    s3.delete_bucket(Bucket=bucket)



_PREFIX = "sim2real-behav-"


def _resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _json_or_none(text):
    try:
        return json.loads(text)
    except ValueError:
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _http(method, url, body=None, headers=None, timeout_s=40):
    """(status, [(lower_header_name, value)], text). A 4xx/5xx is a RESULT, not an exception."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (
                resp.status,
                [(k.lower(), v) for k, v in resp.getheaders()],
                resp.read().decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            [(k.lower(), v) for k, v in exc.headers.items()],
            exc.read().decode("utf-8", "replace"),
        )


def _poll_http(
    url,
    *,
    accept,
    method="GET",
    body=None,
    headers=None,
    timeout_s=150.0,
    interval_s=3.0,
    description="invoke URL",
):
    """Poll an invoke URL until accept(status); return (status, headers, text). RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = (None, [], "")
    while True:
        try:
            last = _http(method, url, body=body, headers=headers)
        except OSError as exc:  # execute-api DNS/TLS still settling
            last = (None, [], f"connection error: {exc}")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} ({url}) never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:300]!r}"
    )


def _invoke_url(ctx, api_endpoint, stage, path):
    """The invoke URL of an HTTP API stage."""
    p = path.lstrip("/")
    return f"{ctx.stage_url(api_endpoint, stage or '$default')}/{p}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
