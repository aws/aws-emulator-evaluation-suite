"""associate-distribution-web-acl-nonexistent-distribution-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-distribution-web-acl-nonexistent-distribution-fails"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _wafv2_client(ctx):
    """WAFv2 web ACLs with Scope=CLOUDFRONT can only be managed via the us-east-1 endpoint."""
    return ctx.client("wafv2", region="us-east-1")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDistributionWebACL against a distribution Id that does not exist is rejected
    with EntityNotFound (the WAF web ACL records no association at all), while the identical
    call against a real distribution succeeds and is reflected in the distribution config."""
    cf = ctx.client("cloudfront")

    acl = _create_web_acl(ctx)
    ctx.on_cleanup(lambda: _delete_web_acl(ctx, acl["Name"], acl["Id"]))

    fake_dist_id = "ENOTAREALDIST0"
    code, msg = _error(
        lambda: cf.associate_distribution_web_acl(Id=fake_dist_id, WebACLArn=acl["ARN"])
    )
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code}"
    not_found_msg = "The specified distribution does not exist."
    assert msg == not_found_msg, f"expected message {not_found_msg!r}, got {msg!r}"

    # effect absent: CloudFront's own web-ACL association API confirms nothing associated.
    # Real AWS omits "Items" entirely from DistributionList when Quantity is 0 (it is not
    # a required member of the shape), so the empty default must feed this assert-empty check.
    associated = cf.list_distributions_by_web_acl_id(WebACLId=acl["ARN"])["DistributionList"].get(
        "Items", []
    )
    assert associated == [], f"expected no associated distributions, got {associated!r}"

    # positive control: associating with a real distribution succeeds
    dist_cfg = _min_distribution_config(ctx)
    created = cf.create_distribution(DistributionConfig=dist_cfg)
    dist = created["Distribution"]
    dist_id = dist["Id"]
    dist_arn = dist["ARN"]
    etag = created["ETag"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]})

    # real AWS requires the distribution's current ETag as IfMatch on this call even though
    # the Smithy model does not mark it required; without it the call fails with
    # InvalidIfMatchVersion.
    cf.associate_distribution_web_acl(Id=dist_id, WebACLArn=acl["ARN"], IfMatch=etag)
    updated_cfg = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    assert updated_cfg["WebACLId"] == acl["ARN"], (
        f"expected WebACLId {acl['ARN']!r}, got {updated_cfg.get('WebACLId')!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_web_acl(ctx):
    wafv2 = _wafv2_client(ctx)
    name = ctx.unique_name("sim2real-acl-")
    resp = wafv2.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": name.replace("-", ""),
        },
        Rules=[],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Summary"]
    return resp


def _delete_web_acl(ctx, name, acl_id):
    wafv2 = _wafv2_client(ctx)
    try:
        lock_token = wafv2.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id)["LockToken"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "WAFNonexistentItemException":
            return
        raise
    try:
        wafv2.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id, LockToken=lock_token)
    except ClientError as err:
        if err.response["Error"]["Code"] not in (
            "WAFNonexistentItemException",
            "WAFAssociatedItemException",
        ):
            raise


def _min_distribution_config(ctx, *, web_acl_id=None, enabled=False):
    origin_id = "sim2real-origin"
    cfg = {
        "CallerReference": ctx.unique_name("sim2real-cf-"),
        "Origins": {
            "Quantity": 1,
            "Items": [{
                "Id": origin_id,
                "DomainName": "www.example.com",
                "CustomOriginConfig": {
                    "HTTPPort": 80,
                    "HTTPSPort": 443,
                    "OriginProtocolPolicy": "https-only",
                },
            }],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
        },
        "Comment": "sim2real behavioral check",
        "Enabled": enabled,
        "ViewerCertificate": {"CloudFrontDefaultCertificate": True},
    }
    if web_acl_id:
        cfg["WebACLId"] = web_acl_id
    return cfg


def _wait_distribution_status(ctx, dist_id, target_status, timeout_s=1500.0, interval_s=15.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        last = resp["Distribution"]["Status"]
        if last == target_status:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"Distribution {dist_id} never reached {target_status} (last={last})")


def _disable_and_delete_distribution(ctx, dist_id, timeout_s=1500.0):
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    _wait_distribution_status(ctx, dist_id, "Deployed", timeout_s=timeout_s)
    etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
