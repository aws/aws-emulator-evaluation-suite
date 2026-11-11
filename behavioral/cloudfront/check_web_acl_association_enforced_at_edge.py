"""web-acl-association-enforced-at-edge."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "web-acl-association-enforced-at-edge"
GROUP = "server-side"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A deployed distribution's domain answers 200, then 403 once a block-all WAF web ACL is associated, then
    200 again once it is disassociated, observed only through HTTPS requests to the distribution."""
    cf = ctx.client("cloudfront")
    domain_name, dist_id = _create_standard_distribution(ctx)
    _wait_distribution_deployed(ctx, dist_id, timeout_s=1200)

    edge, route = ctx.endpoint_route(domain_name)
    url = f"{edge}/"
    baseline = _poll_until_status(url, route, 200, timeout_s=180, interval_s=10, verify=ctx.http_verify)
    assert baseline == 200, f"expected baseline 200 from a freshly deployed distribution, got {baseline!r}"

    web_acl_arn = _create_block_all_web_acl(ctx, dist_id)
    d = cf.get_distribution(Id=dist_id)
    cf.associate_distribution_web_acl(Id=dist_id, IfMatch=d["ETag"], WebACLArn=web_acl_arn)

    blocked = _poll_until_status(url, route, 403, timeout_s=600, interval_s=15, verify=ctx.http_verify)
    assert blocked == 403, f"expected the edge to return 403 once the web ACL blocks all traffic, got {blocked!r}"

    d2 = cf.get_distribution(Id=dist_id)
    cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=d2["ETag"])

    restored = _poll_until_status(url, route, 200, timeout_s=600, interval_s=15, verify=ctx.http_verify)
    assert restored == 200, f"expected the edge to serve traffic again after disassociation, got {restored!r}"


def _http_status(url, route, timeout=10, verify=True):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "sim2real-behavioral-check", **route})
        with urllib.request.urlopen(req, timeout=timeout, context=_https_context(verify)) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, ConnectionError, TimeoutError):  # DNS/edge propagation
        return None


def _poll_until_status(url, route, expected, timeout_s, interval_s, verify=True):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _http_status(url, route, verify=verify)
        if last == expected:
            return last
        time.sleep(interval_s)
    return last


def _create_standard_distribution(ctx):
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-cf-waf-dist-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "sim2real web-acl-enforcement test",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": "docs.aws.amazon.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                        "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
        },
    }
    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    dist_arn = resp["Distribution"]["ARN"]
    domain_name = resp["Distribution"]["DomainName"]
    cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]})
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return domain_name, dist_id


def _wait_distribution_deployed(ctx, dist_id, timeout_s=1200, interval_s=20):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        d = cf.get_distribution(Id=dist_id)
        if d["Distribution"]["Status"] == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError("distribution never reached Deployed status")


def _delete_distribution(ctx, dist_id, timeout_s=1200, interval_s=15):
    cf = ctx.client("cloudfront")
    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    dcfg = cfg["DistributionConfig"]
    if dcfg.get("Enabled"):
        dcfg["Enabled"] = False
        resp = cf.update_distribution(Id=dist_id, DistributionConfig=dcfg, IfMatch=etag)
        etag = resp["ETag"]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        d = cf.get_distribution(Id=dist_id)
        if d["Distribution"]["Status"] == "Deployed":
            etag = d["ETag"]
            break
        time.sleep(interval_s)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_block_all_web_acl(ctx, dist_id):
    # Scope=CLOUDFRONT web ACLs are managed exclusively through the us-east-1 wafv2
    # endpoint, whatever region the check runs in.
    waf = ctx.client("wafv2", region="us-east-1")
    name = ctx.unique_name("sim2real-blockall-")
    resp = waf.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Block": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": name.replace("-", ""),
        },
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    summary = resp["Summary"]
    ctx.on_cleanup(lambda: _delete_web_acl(ctx, dist_id, name, summary["Id"]))
    return summary["ARN"]


def _delete_web_acl(ctx, dist_id, name, web_acl_id):

    cf = ctx.client("cloudfront")
    waf = ctx.client("wafv2", region="us-east-1")
    try:
        d = cf.get_distribution(Id=dist_id)
        if d["Distribution"]["DistributionConfig"].get("WebACLId"):
            cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=d["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFound", "NoSuchDistribution"):
            raise
    g = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id)
    waf.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id, LockToken=g["LockToken"])


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
