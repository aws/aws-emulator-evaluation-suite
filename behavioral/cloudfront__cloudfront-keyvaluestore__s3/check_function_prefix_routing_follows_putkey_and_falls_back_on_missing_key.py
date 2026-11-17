"""function-prefix-routing-follows-putkey-and-falls-back-on-missing-key."""
from __future__ import annotations

import itertools
import json
import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "function-prefix-routing-follows-putkey-and-falls-back-on-missing-key"
GROUP = "routing"
SERVICES = ["cloudfront", "cloudfront-keyvaluestore", "s3"]

_SEQ = itertools.count()
# The managed "CachingDisabled" policy: every viewer request reaches both the function and the
# origin, so what is served is decided by this request's rewrite alone.
_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
_DATAPLANE_TAG = "ROUTING_DATAPLANE_UNREACHABLE"

# cloudfront-js-2.0, viewer-request: looks up the "tenant" query parameter in the associated
# KeyValueStore to get an S3 prefix, and rewrites the URI into that prefix. A tenant with no
# mapping (await rejects) falls back to the fixed "unmapped" prefix.
# Reference: https://docs.aws.amazon.com/code-library/latest/ug/cloudfront_example_cloudfront_functions_kvs_key_value_pairs_section.html
_FUNCTION_CODE = """
import cf from 'cloudfront';
const store = cf.kvs();
async function handler(event) {
    var request = event.request;
    var tenant = request.querystring.tenant ? request.querystring.tenant.value : '';
    var prefix;
    try {
        prefix = await store.get(tenant);
    } catch (err) {
        prefix = 'unmapped';
    }
    request.uri = '/' + prefix + '/page.txt';
    return request;
}
"""


def _raised_code_and_message(call):
    """The Error ``(Code, Message)`` a ClientError carries; raises if the call unexpectedly
    succeeds."""
    try:
        outcome = call()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, call instead returned {outcome!r}")


def _wait_for(read, satisfied, *, budget_s, interval_s, label):
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = read()
        if satisfied(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{label} did not happen within {budget_s}s; last observed {last!r}")


def _until_deployed(cf, dist_id):
    def read():
        return cf.get_distribution(Id=dist_id)["Distribution"]["Status"]

    status = _wait_for(read, lambda s: s == "Deployed", budget_s=1200, interval_s=15,
                        label=f"distribution {dist_id} reaching Deployed")
    assert status == "Deployed", f"distribution {dist_id} status is {status!r}"


def _disable_and_delete_distribution(cf, dist_id):
    try:
        current = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    config, etag = current["DistributionConfig"], current["ETag"]
    if config["Enabled"]:
        config["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=config)
    _until_deployed(cf, dist_id)
    etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_function_once_unreferenced(cf, name, *, budget_s=300.0):
    deadline = time.monotonic() + budget_s
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


def _delete_kvs_once_unreferenced(cf, name, *, budget_s=300.0):
    deadline = time.monotonic() + budget_s
    while True:
        try:
            etag = cf.describe_key_value_store(Name=name)["ETag"]
            cf.delete_key_value_store(Name=name, IfMatch=etag)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "EntityNotFound":
                return
            if code != "CannotDeleteEntityWhileInUse" or time.monotonic() > deadline:
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


def _empty_and_delete_bucket(s3, bucket):
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objects = [{"Key": item["Key"]} for item in page.get("Contents", [])]
            if objects:
                failures = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": objects}
                ).get("Errors")
                assert not failures, f"DeleteObjects left {failures!r} undeleted in {bucket!r}"
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _edge_get(url, satisfied, label, *, headers, verify, budget_s=240.0):
    """GET through the distribution until satisfied(response); keeps the last transport error so
    an expiry names it instead of reading as a bare timeout."""
    last_exc = []

    def fetch():
        try:
            return requests.get(url, headers=headers, timeout=15, verify=verify)
        except requests.RequestException as exc:
            last_exc.append(exc)
            return None

    try:
        return _wait_for(fetch, lambda r: r is not None and satisfied(r), budget_s=budget_s,
                          interval_s=5, label=label)
    except AssertionError as exc:
        tail = f" (last transport error: {last_exc[-1]!r})" if last_exc else ""
        raise AssertionError(f"{_DATAPLANE_TAG}: {exc}{tail}") from exc


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A viewer-request function maps a query key through a KeyValueStore to an S3 prefix and
    serves that prefix's object; PutKey retargets the mapping, and an unmapped key falls back
    to the fixed prefix.
    """
    cf = ctx.client("cloudfront")
    kvs = ctx.client("cloudfront-keyvaluestore")
    s3 = ctx.client("s3")

    store_name = ctx.unique_name("sim2real-routing-kvs-")
    store_arn = cf.create_key_value_store(
        Name=store_name, Comment="sim2real prefix routing map",
    )["KeyValueStore"]["ARN"]
    ctx.on_cleanup(lambda: _delete_kvs_once_unreferenced(cf, store_name))
    status = _wait_for(
        lambda: cf.describe_key_value_store(Name=store_name)["KeyValueStore"]["Status"],
        lambda s: s == "READY", budget_s=300, interval_s=5,
        label=f"key value store {store_name} reaching READY",
    )
    assert status == "READY", f"key value store {store_name} status is {status!r}"

    bucket = ctx.unique_name("sim2real-routing-bkt-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )

    prefix_one, prefix_two, prefix_default = "tenant-acme", "tenant-globex", "unmapped"
    body_one = b"sim2real object served from the acme prefix"
    body_two = b"sim2real object served from the globex prefix"
    body_default = b"sim2real object served from the unmapped-fallback prefix"
    for prefix, body in ((prefix_one, body_one), (prefix_two, body_two),
                        (prefix_default, body_default)):
        s3.put_object(Bucket=bucket, Key=f"{prefix}/page.txt", Body=body, ContentType="text/plain")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-routing-oac-"),
        "Description": "sim2real prefix routing origin lock",
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac(cf, oac_id))

    tenant_key = "acme-co"
    put_one = kvs.put_key(
        KvsARN=store_arn, Key=tenant_key, Value=prefix_one,
        IfMatch=kvs.describe_key_value_store(KvsARN=store_arn)["ETag"],
    )
    assert put_one["ItemCount"] == 1, f"ItemCount after the first PutKey is {put_one['ItemCount']!r}"

    fn_name = ctx.unique_name("sim2real-routing-fn-")
    created_fn = cf.create_function(
        Name=fn_name,
        FunctionConfig={
            "Comment": "sim2real kvs prefix routing",
            "Runtime": "cloudfront-js-2.0",
            "KeyValueStoreAssociations": {"Quantity": 1, "Items": [{"KeyValueStoreARN": store_arn}]},
        },
        FunctionCode=_FUNCTION_CODE.encode(),
    )
    ctx.on_cleanup(lambda: _delete_function_once_unreferenced(cf, fn_name))
    published = cf.publish_function(Name=fn_name, IfMatch=created_fn["ETag"])
    fn_meta = published["FunctionSummary"]["FunctionMetadata"]
    assert fn_meta["Stage"] == "LIVE", f"PublishFunction left the function at {fn_meta['Stage']!r}"
    fn_arn = fn_meta["FunctionARN"]

    dist_config = {
        "CallerReference": f"sim2real-routing-{ctx.unique_name('d')}-{next(_SEQ)}",
        "Comment": "sim2real kvs prefix routing",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "sim2real-s3-origin",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "sim2real-s3-origin",
            "ViewerProtocolPolicy": "https-only",
            "CachePolicyId": _CACHING_DISABLED_POLICY_ID,
            "FunctionAssociations": {
                "Quantity": 1,
                "Items": [{"FunctionARN": fn_arn, "EventType": "viewer-request"}],
            },
        },
    }
    created_dist = cf.create_distribution(DistributionConfig=dist_config)["Distribution"]
    dist_id, dist_domain, dist_arn = (
        created_dist["Id"], created_dist["DomainName"], created_dist["ARN"],
    )
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
        }],
    }))
    _until_deployed(cf, dist_id)
    edge, route_headers = ctx.endpoint_route(dist_domain)
    route_url = f"{edge}/page.txt?tenant={tenant_key}"

    served_mapped = _edge_get(
        route_url, lambda r: r.status_code == 200 and r.content == body_one,
        f"the edge serving the {prefix_one!r}-prefixed object for tenant {tenant_key!r}",
        headers=route_headers, verify=ctx.http_verify,
    )
    assert served_mapped.content == body_one, (
        f"edge served {served_mapped.content!r} for a key mapped to {prefix_one!r}, "
        f"expected {body_one!r}"
    )

    put_two = kvs.put_key(
        KvsARN=store_arn, Key=tenant_key, Value=prefix_two,
        IfMatch=kvs.describe_key_value_store(KvsARN=store_arn)["ETag"],
    )
    assert put_two["ItemCount"] == 1, (
        f"ItemCount after retargeting an existing key is {put_two['ItemCount']!r}, expected 1"
    )

    served_retargeted = _edge_get(
        route_url, lambda r: r.status_code == 200 and r.content == body_two,
        f"the edge serving the {prefix_two!r}-prefixed object after PutKey retargeted {tenant_key!r}",
        headers=route_headers, verify=ctx.http_verify,
    )
    assert served_retargeted.content == body_two, (
        f"after PutKey retargeted {tenant_key!r} to {prefix_two!r}, edge served "
        f"{served_retargeted.content!r}, expected {body_two!r}"
    )

    unmapped_key = ctx.unique_name("no-such-tenant-")
    served_fallback = _edge_get(
        f"{edge}/page.txt?tenant={unmapped_key}",
        lambda r: r.status_code == 200 and r.content == body_default,
        f"the edge falling back to the {prefix_default!r} prefix for the unmapped key "
        f"{unmapped_key!r}",
        headers=route_headers, verify=ctx.http_verify,
    )
    assert served_fallback.content == body_default, (
        f"a tenant with no KeyValueStore entry served {served_fallback.content!r}, expected the "
        f"fallback prefix object {body_default!r}"
    )

    missing_code, missing_message = _raised_code_and_message(
        lambda: kvs.get_key(KvsARN=store_arn, Key=unmapped_key))
    assert missing_code == "ResourceNotFoundException", (
        f"GetKey for the never-written key {unmapped_key!r} returned {missing_code!r}, "
        f"expected ResourceNotFoundException"
    )
    assert missing_message == "No such Key exists", (
        f"GetKey for the never-written key {unmapped_key!r} raised the message "
        f"{missing_message!r}, expected 'No such Key exists'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
