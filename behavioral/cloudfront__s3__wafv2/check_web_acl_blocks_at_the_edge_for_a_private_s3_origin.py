"""web-acl-blocks-at-the-edge-for-a-private-s3-origin."""
from __future__ import annotations

import json
import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "web-acl-blocks-at-the-edge-for-a-private-s3-origin"
GROUP = "web-acl-association"
SERVICES = ["cloudfront", "s3", "wafv2"]

#: CloudFront's control plane, and the only region a CLOUDFRONT-scope WAFv2 resource may live in.
GLOBAL_REGION = "us-east-1"
#: The header a viewer sends to trigger the web ACL's block rule.
BLOCK_HEADER = "x-sim-block"
BLOCK_VALUE = "1"
#: The managed CachingDisabled cache policy, so a block never masks a cached 200 or vice versa.
CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
#: The longest wait for a distribution to reach Deployed, in either direction.
_DEPLOYED_DEADLINE_S = 1200
#: A data-plane FAIL marker distinguishing a real 403 from a connection error during propagation.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
OBJECT_BYTES = b'{"greeting": "hello from a private origin"}'


@tags("axis:rejection", "concern:data-plane", "concern:e2e", "concern:negative-classes",
      "plane:data", "dp:endpoint", "cap:c7")
def run(ctx) -> None:
    """A CLOUDFRONT-scope web ACL blocks a header-matching request at the edge before the private
    S3 origin is reached, and GetSampledRequests attributes the block to the rule.

    Reference: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl.html
    Reference: https://docs.aws.amazon.com/waf/latest/APIReference/API_GetSampledRequests.html
    """
    cf = ctx.client("cloudfront", region=GLOBAL_REGION)
    waf = ctx.client("wafv2", region=GLOBAL_REGION)
    s3 = ctx.client("s3")

    bucket = _create_private_bucket(ctx, s3)
    key = f"{ctx.unique_name('sim2real-cfwaf-').lower()}/index.json"
    s3.put_object(Bucket=bucket, Key=key, Body=OBJECT_BYTES, ContentType="application/json")

    oac_id = _create_oac(ctx, cf, ctx.unique_name("sim2real-cfwaf-"))
    acl_name, acl = _create_web_acl(ctx, waf)
    dist = _create_distribution(ctx, cf, _distribution_config(
        ctx.unique_name("sim2real-cfwaf-"), _origin_host(bucket, ctx.region), oac_id, acl["ARN"]))
    _wait_deployed(cf, dist["Id"])

    _grant_cloudfront_read(s3, bucket, dist["ARN"])
    url, route_headers = ctx.endpoint_route(f"{dist['DomainName']}/{key}")

    served = _edge_get(url, route_headers, 200, verify=ctx.http_verify, timeout_s=300)
    assert served.content == OBJECT_BYTES, (
        f"the unblocked request did not serve the object's bytes: {served.content[:120]!r}"
    )

    headers_with_block = dict(route_headers)
    headers_with_block[BLOCK_HEADER] = BLOCK_VALUE
    blocked = _edge_get(url, headers_with_block, 403, verify=ctx.http_verify, timeout_s=300)
    assert OBJECT_BYTES not in blocked.content, (
        f"the blocked request's body carries the object's bytes: {blocked.content[:200]!r}"
    )

    # Control: the SAME url, header removed, is served again — the 403 above is this header, not
    # the distribution or the object.
    recovered = _edge_get(url, route_headers, 200, verify=ctx.http_verify, timeout_s=300)
    assert recovered.content == OBJECT_BYTES, (
        f"the object stopped being served once the header was removed: "
        f"{recovered.content[:120]!r}"
    )

    sample = _poll_until(
        lambda: waf.get_sampled_requests(
            WebAclArn=acl["ARN"], RuleMetricName=_METRIC_NAME, Scope="CLOUDFRONT",
            TimeWindow={"StartTime": time.time() - 1800, "EndTime": time.time()},
            MaxItems=500),
        lambda d: _find_sample(d, key),
        timeout_s=300, interval_s=10.0,
        description="GetSampledRequests to return a sample naming this run's object key")
    hit = _find_sample(sample, key)
    assert hit["Action"] == "BLOCK", (
        f"the sample for the blocked request does not report the BLOCK action: {hit['Action']!r}"
    )
    header_values = {h["Name"].lower(): h["Value"] for h in hit["Request"].get("Headers", [])}
    assert header_values.get(BLOCK_HEADER) == BLOCK_VALUE, (
        f"the sampled request does not carry the header that triggered the block: {header_values!r}"
    )
    assert sample["PopulationSize"] > 0, (
        f"GetSampledRequests reported PopulationSize 0 for a rule that demonstrably blocked a "
        f"request: {sample['PopulationSize']!r}"
    )


_METRIC_NAME = "block-sim-header"


def _find_sample(response: dict, key: str) -> dict | None:
    for sampled in response.get("SampledRequests", []):
        if key in sampled["Request"].get("URI", ""):
            return sampled
    return None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last: {last!r})")


def _edge_once(url: str, headers: dict, verify):
    """One GET through the edge. A connection error while a new domain propagates is returned,
    not raised, so the poll can keep going and quote it."""
    try:
        return requests.get(url, headers=headers, timeout=20, verify=verify)
    except requests.RequestException as exc:
        return exc


def _edge_get(url: str, headers: dict, want: int, *, verify, timeout_s: float):
    try:
        return _poll_until(lambda: _edge_once(url, headers, verify),
                           lambda r: isinstance(r, requests.Response) and r.status_code == want,
                           timeout_s=timeout_s, interval_s=5.0,
                           description=f"{url} answering {want}")
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc


def _create_private_bucket(ctx, s3) -> str:
    """A bucket with every public-access block on, no bucket policy yet."""
    bucket = ctx.unique_name("sim2real-cfwaf-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(_teardown(lambda: _empty_and_delete_bucket(s3, bucket), "NoSuchBucket"))
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in (page.get("Versions") or []) + (page.get("DeleteMarkers") or [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=bucket)


def _grant_cloudfront_read(s3, bucket: str, dist_arn: str) -> None:
    """The one statement an OAC-signed fetch needs: GetObject, scoped to this distribution."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipalReadOnly",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:{dist_arn.split(':')[1]}:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
        }],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _origin_host(bucket: str, region: str) -> str:
    return f"{bucket}.s3.{region}.amazonaws.com"


def _create_oac(ctx, cf, name: str) -> str:
    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": name,
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]

    def _delete() -> None:
        try:
            cf.delete_origin_access_control(
                Id=oac_id, IfMatch=cf.get_origin_access_control(Id=oac_id)["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchOriginAccessControl":
                raise

    ctx.on_cleanup(_delete)
    return oac_id


def _create_web_acl(ctx, waf) -> tuple[str, dict]:
    """A CLOUDFRONT-scope web ACL, default-allow, with one rule blocking header==1."""
    name = ctx.unique_name("sim2real-cfwaf-")
    rule = {
        "Name": "block-sim-header",
        "Priority": 0,
        "Statement": {"ByteMatchStatement": {
            "SearchString": BLOCK_VALUE.encode(),
            "FieldToMatch": {"SingleHeader": {"Name": BLOCK_HEADER}},
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            "PositionalConstraint": "EXACTLY",
        }},
        "Action": {"Block": {}},
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": _METRIC_NAME,
        },
    }
    summary = waf.create_web_acl(
        Name=name, Scope="CLOUDFRONT", DefaultAction={"Allow": {}}, Rules=[rule],
        VisibilityConfig={"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                          "MetricName": name},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_web_acl(waf, name, summary["Id"]))
    return name, summary


def _delete_web_acl(waf, name: str, acl_id: str) -> None:
    try:
        token = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id)["LockToken"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "WAFNonexistentItemException":
            return
        raise
    try:
        waf.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id, LockToken=token)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


def _distribution_config(caller_ref: str, origin_host: str, oac_id: str, web_acl_arn: str) -> dict:
    return {
        "CallerReference": caller_ref,
        "Comment": "sim2real web acl edge block",
        "Enabled": True,
        "WebACLId": web_acl_arn,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "S3Origin",
            "DomainName": origin_host,
            "OriginAccessControlId": oac_id,
            "S3OriginConfig": {"OriginAccessIdentity": ""},
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "S3Origin",
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": CACHING_DISABLED,
        },
    }


def _create_distribution(ctx, cf, config: dict) -> dict:
    dist = cf.create_distribution(DistributionConfig=config)["Distribution"]
    ctx.on_cleanup(lambda: _retire_distribution(cf, dist["Id"]))
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": [{"Key": "sim2real", "Value": CHECK}]})
    return dist


def _wait_deployed(cf, dist_id: str) -> str:
    holder = {"etag": ""}

    def probe() -> str:
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=_DEPLOYED_DEADLINE_S, interval_s=10.0,
               description=f"distribution {dist_id} reaching Deployed")
    return holder["etag"]


def _retire_distribution(cf, dist_id: str) -> None:
    """Clear the web ACL association, disable, wait for Deployed, then delete. The id is
    server-minted."""
    try:
        resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg, etag = resp["DistributionConfig"], resp["ETag"]
    if cfg.get("Enabled") or cfg.get("WebACLId"):
        cfg["Enabled"] = False
        cfg["WebACLId"] = ""
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
    etag = _wait_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
