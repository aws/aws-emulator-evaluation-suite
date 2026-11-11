"""deep-cloudfront-1-cf-edge-fn-lambda-edge-unqualified-arn-rejected."""
from __future__ import annotations

import itertools
import json
import io
import zipfile
import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudfront-1-cf-edge-fn-lambda-edge-unqualified-arn-rejected"
GROUP = 'edge-functions'
SERVICES = ['cloudfront']


_COUNTER = itertools.count()
# Managed "CachingDisabled": every request reaches the function AND the origin, so what is served
# is decided by this request's rewrite, never by an earlier request's cached object.
CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
# Tags a Deployed distribution that never serves as a data-plane failure, so the transport error
# behind it is not read as an environment problem.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _error(fn):
    """The AWS error (code, message) fn raises. An unexpected SUCCESS raises, never returns a falsy code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
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


_EDGE_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": ["lambda.amazonaws.com", "edgelambda.amazonaws.com"]},
                   "Action": "sts:AssumeRole"}],
}
_HANDLER = "exports.handler = async (event) => event.Records[0].cf.request;\n"


def _zip(source):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("index.js", source)
    return buf.getvalue()


def _create_edge_function(lam, name, role_arn):
    """CreateFunction, retrying ONLY the IAM-propagation refusal of a just-created role."""
    deadline = time.monotonic() + 120
    while True:
        try:
            return lam.create_function(
                FunctionName=name, Runtime="nodejs22.x", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": _zip(_HANDLER)}, Description="sim2real lambda@edge probe",
                Tags={"sim2real": "cf-edge-fn"})
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            if (exc.response["Error"]["Code"] != "InvalidParameterValueException"
                    or "cannot be assumed" not in msg or time.monotonic() > deadline):
                raise
            time.sleep(5)


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:control",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Associating a Lambda@Edge function by its unqualified ARN is rejected, the distribution
    config stays without the association, and the edge keeps serving the origin, while a published
    version of the same function exists.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    lam = ctx.client("lambda", region="us-east-1")  # Lambda@Edge functions live only in us-east-1

    name = ctx.unique_name("sim2real-cfedge-le-")
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(_EDGE_TRUST),
                               Description="sim2real lambda@edge probe")["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    fn = _create_edge_function(lam, name, role_arn)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    version = lam.publish_version(FunctionName=name)
    assert version["Version"] == "1", f"first PublishVersion returned {version['Version']!r}"
    assert version["FunctionArn"] == f"{fn['FunctionArn']}:1", (
        f"published ARN {version['FunctionArn']!r} is not the function ARN qualified by ':1'")

    body = b"sim2real lambda@edge negative - untouched origin object"
    bucket = _make_bucket(ctx, s3, {"index.txt": (body, {})})
    oac_id = _make_oac(ctx, cf)
    dist_id, domain = _create_distribution(ctx, cf, s3, bucket, oac_id, _behavior([]))
    # Break exactly one thing: the unqualified ARN, on an otherwise valid behaviour.
    cur = cf.get_distribution_config(Id=dist_id)
    cfg = cur["DistributionConfig"]
    cfg["DefaultCacheBehavior"]["LambdaFunctionAssociations"] = {"Quantity": 1, "Items": [{
        "LambdaFunctionARN": fn["FunctionArn"], "EventType": "viewer-request",
        "IncludeBody": False}]}
    code, msg = _error(lambda: cf.update_distribution(Id=dist_id, IfMatch=cur["ETag"],
                                                      DistributionConfig=cfg))
    assert code == "InvalidLambdaFunctionAssociation", (
        f"associating the unqualified Lambda ARN failed with {code!r}, expected "
        f"InvalidLambdaFunctionAssociation")
    unqualified_msg = (
        "The function ARN must reference a specific function version. (The ARN must end "
        f"with the version number.) ARN: {fn['FunctionArn']}")
    assert msg == unqualified_msg, f"expected message {unqualified_msg!r}, got {msg!r}"

    after = cf.get_distribution_config(Id=dist_id)
    assoc = after["DistributionConfig"]["DefaultCacheBehavior"].get(
        "LambdaFunctionAssociations", {})
    assert assoc.get("Quantity", 0) == 0, (
        f"the rejected association is present in the config anyway: {assoc!r}")
    assert after["ETag"] == cur["ETag"], (
        f"the rejected update moved the config ETag {cur['ETag']!r} -> {after['ETag']!r}")

    # Positive control on the same distribution: it deploys and serves the origin bytes.
    _wait_deployed(cf, dist_id)
    edge, route = ctx.endpoint_route(domain)
    served = _edge_get(f"{edge}/index.txt", lambda r: r.status_code == 200,
                       "200 from the distribution the rejected association left untouched",
                       headers=route)
    assert served.content == body, f"edge served {served.content!r}, expected {body!r}"
    _teardown_now("distribution", lambda: _delete_distribution(cf, dist_id))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
