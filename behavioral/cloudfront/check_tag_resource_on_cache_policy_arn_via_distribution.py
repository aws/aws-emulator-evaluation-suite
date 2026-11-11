"""tag-resource-on-cache-policy-arn-via-distribution."""
from __future__ import annotations

import time
import itertools

from botocore.exceptions import ClientError

from behavioral_harness import tags

_COUNTER = itertools.count()

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")

def _wait_distribution_deployed(cf, dist_id, timeout_s=1200, interval_s=15, etag_hint=None):
    """Poll GetDistribution until Status == 'Deployed'; return the latest ETag."""
    holder = {"etag": etag_hint}
    def probe():
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]
    _poll_until(probe, lambda status: status == "Deployed", timeout_s=timeout_s, interval_s=interval_s)
    return holder["etag"]

def _force_delete_distribution(cf, dist_id):
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id, etag_hint=etag)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)

def _caller_reference(ctx, prefix="cf"):
    return ctx.unique_name(f"sim2real-behav-{prefix}-") + f"-{next(_COUNTER)}"

def _minimal_distribution_config(ctx, comment="", origin_domain=None, origin_id="primary-origin"):
    """Build a minimal-but-valid DistributionConfig with a single custom origin."""
    domain = origin_domain or f"{ctx.unique_name('sim2real-behav-origin-')}.example.com"
    origins = [{
        "Id": origin_id,
        "DomainName": domain,
        "CustomOriginConfig": {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            "OriginReadTimeout": 30,
            "OriginKeepaliveTimeout": 5,
        },
    }]
    return {
        "CallerReference": _caller_reference(ctx),
        "Comment": comment,
        "Enabled": True,
        "Origins": {"Quantity": len(origins), "Items": origins},
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # Managed-CachingOptimized
        },
    }

def _create_distribution(cf, ctx, **kwargs):
    cfg = _minimal_distribution_config(ctx, **kwargs)
    resp = cf.create_distribution(DistributionConfig=cfg)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    return resp

def _error(fn):
    """Call fn and return (code, message); raise if it unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("expected the call to be rejected, it succeeded")

CHECK = "tag-resource-on-cache-policy-arn-via-distribution"
GROUP = 'tagging'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tagging round-trips on a distribution's ARN (never-tagged lists empty), while TagResource,
    ListTagsForResource and UntagResource all reject the ARN of the cache policy attached to that
    distribution with InvalidArgument: cache-policy is not a taggable resource type.
    """
    cf = ctx.client("cloudfront")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    dist_resp = _create_distribution(cf, ctx, comment="tag-cache-policy-via-distribution")
    dist_arn = dist_resp["Distribution"]["ARN"]
    policy_id = dist_resp["Distribution"]["DistributionConfig"]["DefaultCacheBehavior"]["CachePolicyId"]

    # A never-tagged resource returns an empty Items list, not an error — distinguishing "no
    # tags" from "resource missing".
    pre = cf.list_tags_for_resource(Resource=dist_arn)
    assert pre["Tags"]["Items"] == [], f"expected no tags before any TagResource call, got {pre['Tags']['Items']}"

    # Positive control: the round trip works on the distribution's own ARN, so the account and
    # credentials are otherwise healthy for CloudFront tagging.
    tag_key = "sim2real-behav-b2-tagkey"
    cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": tag_key, "Value": "v1"}]})
    listed = cf.list_tags_for_resource(Resource=dist_arn)
    tag_map = {t["Key"]: t.get("Value") for t in listed["Tags"]["Items"]}
    assert tag_map.get(tag_key) == "v1", f"expected tag {tag_key}=v1 on the distribution, got {tag_map}"

    cf.untag_resource(Resource=dist_arn, TagKeys={"Items": [tag_key]})
    listed2 = cf.list_tags_for_resource(Resource=dist_arn)
    tag_map2 = {t["Key"]: t.get("Value") for t in listed2["Tags"]["Items"]}
    assert tag_key not in tag_map2, f"expected tag removed by UntagResource, still present: {tag_map2}"

    # The actual subject: a cache-policy ARN, derived from this same distribution's
    # DefaultCacheBehavior.CachePolicyId — not a resource type CloudFront's tagging API accepts.
    policy_arn = f"arn:aws:cloudfront::{account_id}:cache-policy/{policy_id}"

    expected_message = "The parameter resource type: cache-policy is invalid."
    tag_code, tag_msg = _error(lambda: cf.tag_resource(Resource=policy_arn, Tags={"Items": [{"Key": tag_key, "Value": "v1"}]}))
    assert tag_code == "InvalidArgument", f"expected TagResource to reject a cache-policy ARN with InvalidArgument, got {tag_code}: {tag_msg}"
    assert tag_msg == expected_message, f"expected message {expected_message!r}, got {tag_msg!r}"

    list_code, list_msg = _error(lambda: cf.list_tags_for_resource(Resource=policy_arn))
    assert list_code == "InvalidArgument", f"expected ListTagsForResource to reject a cache-policy ARN with InvalidArgument, got {list_code}: {list_msg}"
    assert list_msg == expected_message, f"expected message {expected_message!r}, got {list_msg!r}"

    untag_code, untag_msg = _error(lambda: cf.untag_resource(Resource=policy_arn, TagKeys={"Items": [tag_key]}))
    assert untag_code == "InvalidArgument", f"expected UntagResource to reject a cache-policy ARN with InvalidArgument, got {untag_code}: {untag_msg}"
    assert untag_msg == expected_message, f"expected message {expected_message!r}, got {untag_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
