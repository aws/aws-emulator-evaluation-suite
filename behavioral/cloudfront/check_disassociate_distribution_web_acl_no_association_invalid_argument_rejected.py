"""disassociate-distribution-web-acl-no-association-invalid-argument-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disassociate-distribution-web-acl-no-association-invalid-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With no web ACL associated, DisassociateDistributionWebACL with the right IfMatch is a no-op
    (WebACLId stays empty); omitting the model-optional IfMatch is rejected with
    InvalidIfMatchVersion, and disassociating a real web ACL clears WebACLId."""
    cf = ctx.client("cloudfront")
    dist_id, etag = _create_minimal_distribution(ctx)

    pre_cfg = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    assert not pre_cfg.get("WebACLId"), "fixture distribution unexpectedly already has a web ACL"

    # Break: omit the (model-optional, service-enforced) IfMatch precondition.
    code, message = _error(lambda: cf.disassociate_distribution_web_acl(Id=dist_id))
    assert code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion, got {code}"
    assert message == "The If-Match version is missing or not valid for the resource.", f"unexpected InvalidIfMatchVersion message: {message!r}"

    # Effect absent: the rejected call left config and the ETag untouched.
    rejected = cf.get_distribution_config(Id=dist_id)
    assert not rejected["DistributionConfig"].get("WebACLId")
    assert rejected["ETag"] == etag, "a rejected call must not advance the distribution's ETag"

    # Restore: supply the correct IfMatch. The identical call now succeeds --
    # disassociating when nothing is associated is a legal, idempotent no-op.
    noop = cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=etag)
    assert noop["Id"] == dist_id
    etag = noop["ETag"]
    still_cfg = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    assert not still_cfg.get("WebACLId")

    # positive control: associate a real web ACL, then disassociate succeeds
    acl_arn, cleanup_acl = _create_cloudfront_web_acl(ctx)
    ctx.on_cleanup(cleanup_acl)

    assoc = cf.associate_distribution_web_acl(Id=dist_id, WebACLArn=acl_arn, IfMatch=etag)
    etag = assoc["ETag"]
    associated_cfg = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    assert associated_cfg["WebACLId"] == acl_arn

    disassoc = cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=etag)
    assert disassoc["Id"] == dist_id
    cleared_cfg = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    assert not cleared_cfg.get("WebACLId")


# ===== helpers =====

def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_minimal_distribution(ctx) -> tuple[str, str]:
    cf = ctx.client("cloudfront")
    origin_id = "sim2real-origin"
    config = {
        "CallerReference": ctx.unique_name("sim2real-cf-std-"),
        "Comment": "sim2real behavioral fixture (standard)",
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": origin_id,
                    "DomainName": "origin.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "http-only",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",  # AWS managed "CachingDisabled"
        },
    }
    dist = cf.create_distribution(DistributionConfig=config)
    dist_id = dist["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return dist_id, dist["ETag"]


def _delete_distribution(ctx, dist_id) -> None:
    cf = ctx.client("cloudfront")
    etag = None
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            d = cf.get_distribution(Id=dist_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchDistribution":
                raise
            return
        if d["Distribution"]["Status"] == "Deployed":
            etag = d["ETag"]
            break
        time.sleep(15)
    if etag is None:
        try:
            etag = cf.get_distribution(Id=dist_id)["ETag"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchDistribution":
                raise
            return
    try:
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise


def _wafv2_cloudfront_client(ctx):
    """WAFv2 web ACLs with Scope="CLOUDFRONT" are global but must be managed via
    the us-east-1 endpoint specifically -- any other region rejects with
    WAFInvalidParameterException ("The scope is not valid.")."""
    return ctx.client("wafv2", region="us-east-1")


def _create_cloudfront_web_acl(ctx):
    wafv2 = _wafv2_cloudfront_client(ctx)
    name = ctx.unique_name("sim2real-cf-acl-")
    summary = wafv2.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": name.replace("-", ""),
        },
    )["Summary"]

    def _cleanup():
        # Retry while the disassociation propagates (WAFAssociatedItemException) or a concurrent
        # edit moved the lock token (WAFOptimisticLockException); raise anything else.
        deadline = time.monotonic() + 120
        while True:
            try:
                token = wafv2.get_web_acl(
                    Name=summary["Name"], Scope="CLOUDFRONT", Id=summary["Id"]
                )["LockToken"]
                wafv2.delete_web_acl(
                    Name=summary["Name"], Scope="CLOUDFRONT", Id=summary["Id"], LockToken=token
                )
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "WAFNonexistentItemException":
                    return
                if code not in ("WAFAssociatedItemException", "WAFOptimisticLockException"):
                    raise
                if time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    return summary["ARN"], _cleanup


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
