"""e2e-web-acl-association-changes-distribution-behavior."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-web-acl-association-changes-distribution-behavior"
GROUP = "e2e"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associating/disassociating a WAF web ACL is reflected in, then reverted from, the distribution config."""
    cf = ctx.client("cloudfront")
    # WAFv2 CLOUDFRONT-scope web ACLs are created via the us-east-1 endpoint.
    waf = ctx.client("wafv2", region="us-east-1")

    acl_name = ctx.unique_name("sim2real-cf-acl-")
    created_acl = waf.create_web_acl(
        Name=acl_name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        Rules=[],
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": acl_name.replace("-", ""),
        },
        Tags=[{"Key": "sim2real-behavioral", "Value": acl_name}],
    )["Summary"]
    acl_id = created_acl["Id"]
    acl_arn = created_acl["ARN"]

    dist_id, _ = _create_distribution(ctx, cf, enabled=False)
    # Registered first so LIFO cleanup runs it LAST: deleting the distribution blocks on
    # Deployed status (minutes) and can exhaust the whole bounded cleanup window, so the cheap,
    # near-instant web ACL delete below must run before it, not after.
    ctx.on_cleanup(lambda: _cleanup_distribution(cf, dist_id))
    ctx.on_cleanup(lambda: _delete_web_acl(waf, acl_name, acl_id))

    before = cf.get_distribution(Id=dist_id)
    before_web_acl_id = before["Distribution"]["DistributionConfig"].get("WebACLId", "")
    assert before_web_acl_id == "", (
        f"expected no WebACLId on a freshly created distribution, got {before_web_acl_id!r}"
    )

    assoc_etag = before["ETag"]
    cf.associate_distribution_web_acl(Id=dist_id, WebACLArn=acl_arn, IfMatch=assoc_etag)

    after_assoc = cf.get_distribution(Id=dist_id)
    after_assoc_web_acl_id = after_assoc["Distribution"]["DistributionConfig"]["WebACLId"]
    assert after_assoc_web_acl_id == acl_arn, (
        f"expected WebACLId={acl_arn!r} on an independent GetDistribution read after "
        f"AssociateDistributionWebACL, got {after_assoc_web_acl_id!r}"
    )

    disassoc_etag = after_assoc["ETag"]
    cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=disassoc_etag)

    after_disassoc = cf.get_distribution(Id=dist_id)
    after_disassoc_web_acl_id = after_disassoc["Distribution"]["DistributionConfig"].get("WebACLId", "")
    assert after_disassoc_web_acl_id == "", (
        f"expected WebACLId cleared on an independent GetDistribution read after "
        f"DisassociateDistributionWebACL, got {after_disassoc_web_acl_id!r}"
    )


def _create_distribution(ctx, cf, *, enabled):
    bucket_domain = f"{ctx.unique_name('sim2real-cf-origin-')}.s3.amazonaws.com"
    cfg = {
        "CallerReference": ctx.unique_name("sim2real-cf-"),
        "Comment": "sim2real behavioral check",
        "Enabled": enabled,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": bucket_domain,
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _MANAGED_CACHING_DISABLED,
        },
    }
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": cfg,
            "Tags": {"Items": [{"Key": "sim2real-behavioral", "Value": cfg["CallerReference"]}]},
        }
    )
    dist = resp["Distribution"]
    return dist["Id"], dist["ARN"]


def _wait_distribution_deployed(cf, dist_id, timeout_s=1500, interval_s=20):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.get_distribution(Id=dist_id)["Distribution"]["Status"]
        if status == "Deployed":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} did not reach Deployed within {timeout_s}s (last={status})")


def _cleanup_distribution(cf, dist_id):
    from botocore.exceptions import ClientError

    try:
        current = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg = current["DistributionConfig"]
    etag = current["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        updated = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
        etag = updated["ETag"]
    _wait_distribution_deployed(cf, dist_id)
    etag = cf.get_distribution_config(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_web_acl(waf, name, acl_id):
    from botocore.exceptions import ClientError

    try:
        got = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "WAFNonexistentItemException":
            return
        raise
    waf.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id, LockToken=got["LockToken"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
