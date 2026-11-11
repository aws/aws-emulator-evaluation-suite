"""web-acl-association-invalid-webacl-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "web-acl-association-invalid-webacl-rejected"
GROUP = "e2e"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDistributionWebACL rejects a well-formed but nonexistent web ACL ARN; a real ACL succeeds."""
    cf = ctx.client("cloudfront")
    waf = _wafv2_cloudfront_client(ctx)
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    dist_id, _ = _create_distribution(ctx, cf, enabled=False)
    ctx.on_cleanup(lambda: _cleanup_distribution(cf, dist_id))

    before = cf.get_distribution(Id=dist_id)
    before_webacl = before["Distribution"]["DistributionConfig"].get("WebACLId", "")
    assert before_webacl == "", f"expected a freshly created distribution to have no WebACLId, got {before_webacl!r}"

    # WAFv2 CLOUDFRONT-scope web ACL ARNs are always us-east-1, regardless of
    # the harness's own region -- see _wafv2_cloudfront_client below.
    bogus_arn = f"arn:aws:wafv2:us-east-1:{account_id}:global/webacl/does-not-exist/{uuid.uuid4()}"
    etag = before["ETag"]
    code, message = _error_code_and_message(
        lambda: cf.associate_distribution_web_acl(Id=dist_id, WebACLArn=bogus_arn, IfMatch=etag)
    )
    # Confirmed against real AWS: CloudFront validates the referenced web ACL (existence +
    # CLOUDFRONT-scope eligibility) as an InvalidArgument, not an EntityNotFound -- unlike
    # AssociateDistributionTenantWebACL's nonexistent-id path, which is EntityNotFound.
    assert code == "InvalidArgument", f"expected InvalidArgument for a nonexistent web ACL ARN, got {code!r}"
    expected = (
        "The specified web ACL isn't valid. Specify a web ACL that was previously validated "
        "and try again."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the distribution config was not mutated by the rejected call
    unchanged = cf.get_distribution(Id=dist_id)
    unchanged_webacl = unchanged["Distribution"]["DistributionConfig"].get("WebACLId", "")
    assert unchanged_webacl == "", f"expected WebACLId to remain unset after the rejected call, got {unchanged_webacl!r}"

    # positive control: associating a real web ACL with the same distribution succeeds
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Summary"]
    acl_id = created_acl["Id"]
    acl_arn = created_acl["ARN"]
    ctx.on_cleanup(lambda: _delete_web_acl(waf, acl_name, acl_id))
    # cleanup runs last-in first-out: detach the ACL before it is deleted
    ctx.on_cleanup(lambda: _disassociate_web_acl(cf, dist_id))

    cf.associate_distribution_web_acl(Id=dist_id, WebACLArn=acl_arn, IfMatch=unchanged["ETag"])
    after = cf.get_distribution(Id=dist_id)
    after_webacl = after["Distribution"]["DistributionConfig"]["WebACLId"]
    assert after_webacl == acl_arn, f"expected the real web ACL {acl_arn!r} to associate, got WebACLId={after_webacl!r}"


def _wafv2_cloudfront_client(ctx):
    """WAFv2 web ACLs with Scope="CLOUDFRONT" are global but are managed only through the
    us-east-1 endpoint; any other region rejects with WAFInvalidParameterException ("The scope
    is not valid."). Pin that region on the target's own client."""
    return ctx.client("wafv2", region="us-east-1")


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


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
    resp = cf.create_distribution(DistributionConfig=cfg)
    dist = resp["Distribution"]
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]})
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


def _disassociate_web_acl(cf, dist_id):
    from botocore.exceptions import ClientError

    try:
        current = cf.get_distribution(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    if current["Distribution"]["DistributionConfig"].get("WebACLId"):
        cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=current["ETag"])


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
