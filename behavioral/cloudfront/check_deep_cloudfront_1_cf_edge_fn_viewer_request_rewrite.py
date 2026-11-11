"""deep-cloudfront-1-cf-edge-fn-viewer-request-rewrite."""
from __future__ import annotations

import itertools
import json
import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudfront-1-cf-edge-fn-viewer-request-rewrite"
GROUP = 'edge-functions'
SERVICES = ['cloudfront']

# ===== helpers =====

_COUNTER = itertools.count()
# Managed "CachingDisabled": every request reaches the function AND the origin, so what is served
# is decided by this request's rewrite, never by an earlier request's cached object.
CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
# Tags a Deployed distribution that never serves as a data-plane failure, so the transport error
# behind it is not read as an environment problem.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _error_code(fn):
    """The AWS error code fn raises. An unexpected SUCCESS raises, never returns a falsy code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_deployed(cf, dist_id):
    """Poll GetDistribution until Status == 'Deployed'; return the latest ETag."""
    holder = {}

    def probe():
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=1200, interval_s=15,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _delete_distribution(cf, dist_id):
    """Disable, wait for the disable to deploy, delete. Idempotent: gone is done."""
    try:
        resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg, etag = resp["DistributionConfig"], resp["ETag"]
    if cfg["Enabled"]:
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_function(cf, name):
    """ETag-guarded DeleteFunction, retried while CloudFront still reports it in use by the
    distribution that was just deleted. Idempotent."""
    deadline = time.monotonic() + 300
    while True:
        try:
            etag = cf.describe_function(Name=name)["ETag"]
            cf.delete_function(Name=name, IfMatch=etag)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchFunctionExists":
                return
            if code != "FunctionInUse" or time.monotonic() > deadline:
                raise
            time.sleep(10)


def _delete_oac(cf, oac_id):
    try:
        etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchOriginAccessControl":
            return
        raise
    cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)


def _delete_bucket(s3, bucket):
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _teardown_now(label, fn):
    """Run a teardown inside the check body; a failure raises, naming the resource."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - re-raised with the resource named
        raise RuntimeError(f"teardown of {label} failed in-body: {exc!r}") from exc


def _make_bucket(ctx, s3, objects):
    """A private bucket in ctx.region holding ``objects`` ({key: (body, metadata)})."""
    bucket = ctx.unique_name("sim2real-cfedge-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    for key, (body, meta) in objects.items():
        s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain", Metadata=meta)
    return bucket


def _make_oac(ctx, cf):
    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-cfedge-oac-"),
        "Description": "sim2real cf-edge-fn",
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac(cf, oac_id))
    return oac_id


def _make_function(ctx, cf, code, comment, kvs_arn=None):
    """Create a cloudfront-js-2.0 function and publish it to LIVE. -> (name, live ARN)."""
    name = ctx.unique_name("sim2real-cfedge-fn-")
    config = {"Comment": comment, "Runtime": "cloudfront-js-2.0"}
    if kvs_arn:
        config["KeyValueStoreAssociations"] = {"Quantity": 1,
                                               "Items": [{"KeyValueStoreARN": kvs_arn}]}
    created = cf.create_function(Name=name, FunctionConfig=config, FunctionCode=code.encode())
    ctx.on_cleanup(lambda: _delete_function(cf, name))
    published = cf.publish_function(Name=name, IfMatch=created["ETag"])
    meta = published["FunctionSummary"]["FunctionMetadata"]
    assert meta["Stage"] == "LIVE", f"PublishFunction left the function in stage {meta['Stage']!r}"
    return name, meta["FunctionARN"]


def _behavior(fn_assocs, path=None):
    b = {
        "TargetOriginId": "s3-origin",
        "ViewerProtocolPolicy": "https-only",
        "CachePolicyId": CACHING_DISABLED,
        "FunctionAssociations": {"Quantity": len(fn_assocs), "Items": fn_assocs},
    }
    if path:
        b["PathPattern"] = path
    return b


def _create_distribution(ctx, cf, s3, bucket, oac_id, default, extra=()):
    """Distribution over the OAC-locked bucket. Returns (dist_id, domain).

    CallerReference starts `sim2real-cf-` so leftover distributions can be found by prefix."""
    cfg = {
        "CallerReference": f"sim2real-cf-{ctx.unique_name('edge-')}-{next(_COUNTER)}",
        "Comment": "sim2real cf-edge-fn",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3-origin",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": default,
    }
    if extra:
        cfg["CacheBehaviors"] = {"Quantity": len(extra), "Items": list(extra)}
    dist = cf.create_distribution(DistributionConfig=cfg)["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(cf, dist_id))
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist["ARN"]}},
        }],
    }))
    return dist_id, dist["DomainName"]


def _edge_get(url, predicate, description, headers=None, timeout_s=240):
    """GET through the edge until predicate(response) holds. Transport errors are kept, so an
    expiry names its cause instead of `last: None`."""
    errors = []

    def fetch():
        try:
            return requests.get(url, headers=headers or {}, timeout=15)
        except requests.RequestException as exc:
            errors.append(exc)
            return None

    try:
        return _poll_until(fetch, lambda r: r is not None and predicate(r),
                           timeout_s=timeout_s, interval_s=5, description=description)
    except AssertionError as exc:
        tail = f" (last transport error: {errors[-1]!r})" if errors else ""
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}{tail}") from exc

# ===== end helpers =====


# The rewrite is DERIVED from the request: the variant header's value picks the object key. So the
# object that comes back names the URI the function produced, and nothing about the mapping can be
# baked into the origin or a recording.
_FUNCTION_CODE = """
function handler(event) {
    var request = event.request;
    var variant = request.headers['x-sim2real-variant'];
    if (variant && variant.value) {
        request.uri = '/variants/' + variant.value + '.txt';
        request.headers['x-sim2real-rewritten'] = {value: 'yes'};
    }
    return request;
}
"""


def _test_event(uri, variant):
    return json.dumps({
        "version": "1.0",
        "context": {"eventType": "viewer-request"},
        "viewer": {"ip": "203.0.113.10"},
        "request": {"method": "GET", "uri": uri, "querystring": {}, "cookies": {},
                    "headers": {"x-sim2real-variant": {"value": variant}}},
    }).encode()


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A LIVE viewer-request function rewrites the URI in the request path and changes which S3
    object the edge serves, and TestFunction on the same function predicts that exact rewrite.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    token = ctx.unique_name("v")  # e.g. v3f9c..., [a-z0-9] only: safe as a path segment
    default_body = b"sim2real default object - the function did NOT rewrite"
    variant_body = f"sim2real variant object for {token}".encode()
    bucket = _make_bucket(ctx, s3, {
        "index.txt": (default_body, {}),
        f"variants/{token}.txt": (variant_body, {}),
    })
    oac_id = _make_oac(ctx, cf)
    fn_name, fn_arn = _make_function(ctx, cf, _FUNCTION_CODE, "sim2real viewer-request rewrite")

    dist_id, domain = _create_distribution(
        ctx, cf, s3, bucket, oac_id,
        _behavior([{"FunctionARN": fn_arn, "EventType": "viewer-request"}]))
    _wait_deployed(cf, dist_id)
    edge, route = ctx.endpoint_route(domain)
    url = f"{edge}/index.txt"

    # Control: without the header the function passes the request through unchanged.
    plain = _edge_get(url, lambda r: r.status_code == 200,
                      "200 for the un-rewritten /index.txt through the distribution",
                      headers=route)
    assert plain.content == default_body, (
        f"without the variant header the edge served {plain.content!r}, expected the "
        f"/index.txt origin object {default_body!r}")

    # The rewrite: same viewer URL, the function moves it to /variants/<token>.txt.
    rewritten = _edge_get(url, lambda r: r.status_code == 200 and r.content == variant_body,
                          f"the rewritten object for variant {token!r}",
                          headers={"x-sim2real-variant": token, **route})
    assert rewritten.content == variant_body, (
        f"with x-sim2real-variant={token!r} the edge served {rewritten.content!r}; the "
        f"viewer-request rewrite should have served {variant_body!r}")
    assert rewritten.content != plain.content, (
        "the rewritten request served the same bytes as the plain one; the function did "
        "not change which origin object was fetched")
    served_key = f"/variants/{token}.txt"

    # The same LIVE function under TestFunction must predict the rewrite the edge performed.
    etag = cf.describe_function(Name=fn_name, Stage="LIVE")["ETag"]
    result = cf.test_function(Name=fn_name, IfMatch=etag, Stage="LIVE",
                              EventObject=_test_event("/index.txt", token))["TestResult"]
    assert not result.get("FunctionErrorMessage"), (
        f"TestFunction raised: {result.get('FunctionErrorMessage')!r}")
    out = json.loads(result["FunctionOutput"])
    test_req = out.get("request", out)
    assert test_req["uri"] == served_key, (
        f"TestFunction rewrote the URI to {test_req['uri']!r}, but the edge served the "
        f"object at {served_key!r} for the identical input")
    assert test_req["headers"].get("x-sim2real-rewritten") == {"value": "yes"}, (
        f"TestFunction output headers {test_req['headers']!r} lack the header the "
        f"function adds when it rewrites")

    # And for the no-header input TestFunction must agree the URI is left alone.
    plain_event = json.loads(_test_event("/index.txt", token))
    plain_event["request"]["headers"] = {}
    plain_result = cf.test_function(Name=fn_name, IfMatch=etag, Stage="LIVE",
                                    EventObject=json.dumps(plain_event).encode())["TestResult"]
    plain_out = json.loads(plain_result["FunctionOutput"])
    assert plain_out.get("request", plain_out)["uri"] == "/index.txt", (
        f"TestFunction changed a header-less URI to {plain_out!r}; the edge served the "
        f"/index.txt object for that request")
    _teardown_now("distribution", lambda: _delete_distribution(cf, dist_id))
    _teardown_now("function", lambda: _delete_function(cf, fn_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
