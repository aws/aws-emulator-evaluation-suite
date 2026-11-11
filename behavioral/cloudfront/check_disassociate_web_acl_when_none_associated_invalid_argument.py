"""disassociate-web-acl-when-none-associated-invalid-argument."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "disassociate-web-acl-when-none-associated-invalid-argument"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateDistributionWebACL on a distribution with no web ACL succeeds as a no-op (WebACLId
    stays empty); after AssociateDistributionWebACL with a real WAFv2 web ACL sets WebACLId to its
    ARN, the disassociate clears it again."""
    cf = ctx.client("cloudfront")
    dist_id, etag, _dist = _create_minimal_distribution(ctx)

    current = cf.get_distribution_config(Id=dist_id)
    assert current["DistributionConfig"].get("WebACLId", "") == ""

    noop = cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=etag)
    assert noop["Id"] == dist_id, f"expected Id {dist_id!r}, got {noop.get('Id')!r}"
    assert "ETag" in noop

    # Effect absent: still nothing associated.
    current = cf.get_distribution_config(Id=dist_id)
    assert current["DistributionConfig"].get("WebACLId", "") == ""
    etag = current["ETag"]

    # Positive control: associate then disassociate a real web ACL. Both succeed,
    # and each transition is confirmed by an independent read rather than trusting
    # the mutating call's own response.
    web_acl_arn = _create_web_acl(ctx)
    assoc = cf.associate_distribution_web_acl(Id=dist_id, WebACLArn=web_acl_arn, IfMatch=etag)
    etag = assoc["ETag"]
    associated = cf.get_distribution_config(Id=dist_id)
    assert associated["DistributionConfig"].get("WebACLId") == web_acl_arn

    disassoc = cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=etag)
    assert disassoc["Id"] == dist_id
    current = cf.get_distribution_config(Id=dist_id)
    assert current["DistributionConfig"].get("WebACLId", "") == ""


def _minimal_distribution_config(ctx) -> dict:
    return {
        "CallerReference": ctx.unique_name("sim2real-cf-"),
        "Comment": "sim2real disassociate-web-acl-when-none-associated-invalid-argument",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": "www.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                        "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                        "OriginReadTimeout": 30,
                        "OriginKeepaliveTimeout": 5,
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
        },
    }


def _create_minimal_distribution(ctx):
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": _minimal_distribution_config(ctx),
            "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
        }
    )
    dist = resp["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _teardown_distribution(ctx, dist_id))
    return dist_id, resp["ETag"], dist


def _wait_distribution_deployed(ctx, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0):
    import time

    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _teardown_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    config = cfg["DistributionConfig"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
    resp = _wait_distribution_deployed(ctx, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])


def _create_web_acl(ctx) -> str:
    # WAFv2 web ACLs with Scope="CLOUDFRONT" are global but must be managed via the
    # us-east-1 endpoint specifically; any other region rejects them with
    # WAFInvalidParameterException.
    waf = ctx.client("wafv2", region="us-east-1")
    name = ctx.unique_name("sim2real-cf-acl-")
    resp = waf.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        Rules=[],
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": name.replace("-", ""),
        },
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    summary = resp["Summary"]
    web_acl_id = summary["Id"]
    arn = summary["ARN"]
    ctx.on_cleanup(lambda: _delete_web_acl(ctx, name, web_acl_id))
    return arn


def _delete_web_acl(ctx, name: str, web_acl_id: str) -> None:
    waf = ctx.client("wafv2", region="us-east-1")
    lock_token = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id)["LockToken"]
    waf.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id, LockToken=lock_token)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
