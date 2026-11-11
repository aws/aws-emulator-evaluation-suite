"""distribution-web-acl-association-toggles-state."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "distribution-web-acl-association-toggles-state"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDistributionWebACL attaches an ACL visible via GetDistribution, and
    DisassociateDistributionWebACL clears it on the subsequent read."""
    cf = ctx.client("cloudfront")

    dist_id, etag = _create_distribution(ctx)
    initial = cf.get_distribution(Id=dist_id)["Distribution"]["DistributionConfig"]
    assert initial.get("WebACLId", "") == "", f"expected no WebACLId on a fresh distribution, got {initial.get('WebACLId')!r}"

    web_acl_arn = _create_cloudfront_web_acl(ctx)

    assoc = cf.associate_distribution_web_acl(Id=dist_id, WebACLArn=web_acl_arn, IfMatch=etag)
    assert assoc["WebACLArn"] == web_acl_arn, f"expected AssociateDistributionWebACL to echo {web_acl_arn!r}, got {assoc['WebACLArn']!r}"
    etag = assoc["ETag"]

    after_assoc = cf.get_distribution(Id=dist_id)["Distribution"]["DistributionConfig"]
    assert after_assoc["WebACLId"] == web_acl_arn, f"expected GetDistribution to reflect the associated ACL {web_acl_arn!r}, got {after_assoc.get('WebACLId')!r}"

    disassoc = cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=etag)
    etag = disassoc["ETag"]

    after_disassoc = cf.get_distribution(Id=dist_id)["Distribution"]["DistributionConfig"]
    assert after_disassoc.get("WebACLId", "") == "", f"expected GetDistribution to show no WebACLId after disassociation, got {after_disassoc.get('WebACLId')!r}"


def _create_distribution(ctx):
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-dist-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "distribution webacl toggle check",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": "origin.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
        },
    }
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    return dist_id, resp["ETag"]


def _disable_and_delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    config = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        got = cf.get_distribution(Id=dist_id)
        etag = got["ETag"]
        if got["Distribution"]["Status"] == "Deployed":
            break
        time.sleep(20)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_cloudfront_web_acl(ctx) -> str:
    # WAFv2 CLOUDFRONT-scope web ACLs are global but must be managed through the us-east-1
    # endpoint (any other region answers WAFInvalidParameterException "The scope is not
    # valid."). Pinned via ctx.client(..., region=) rather than aborting on ctx.region, so the
    # same code path runs against every target -- an emulator keeps its shared endpoint.
    waf = ctx.client("wafv2", region="us-east-1")
    name = ctx.unique_name("sim2real-acl-")
    resp = waf.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": name.replace("-", "")[:128],
        },
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    summary = resp["Summary"]
    acl_id = summary["Id"]
    arn = summary["ARN"]

    def _cleanup():
        got = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id)
        waf.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id, LockToken=got["LockToken"])

    ctx.on_cleanup(_cleanup)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
