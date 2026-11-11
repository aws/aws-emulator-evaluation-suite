"""distribution-tag-untag-lifecycle."""
from __future__ import annotations

import time
import itertools
from botocore.exceptions import ClientError

from behavioral_harness import tags

_COUNTER = itertools.count()
_NO_SUCH_DISTRIBUTION = "The specified distribution does not exist."
_NO_SUCH_RESOURCE = "The specified resource doesn't exist. Update your request and try again."

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")

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
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchDistribution":
            return  # already deleted by the check body; cleanup is a no-op
        raise
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id, etag_hint=etag)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)

def _caller_reference(ctx, prefix="cf"):
    return ctx.unique_name(f"sim2real-behav-{prefix}-") + f"-{next(_COUNTER)}"

def _minimal_distribution_config(ctx, comment="", enabled=True, origin_domain=None, origin_id="primary-origin", extra_origins=None):
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
    if extra_origins:
        origins.extend(extra_origins)
    return {
        "CallerReference": _caller_reference(ctx),
        "Comment": comment,
        "Enabled": enabled,
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

CHECK = "distribution-tag-untag-lifecycle"
GROUP = 'tagging'
SERVICES = ['cloudfront']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on a distribution ARN, then
    delete proves the ARN is gone and unusable: TagResource against it fails."""
    cf = ctx.client("cloudfront")
    resp = _create_distribution(cf, ctx, comment="tagging")
    dist_arn = resp["Distribution"]["ARN"]
    dist_id = resp["Distribution"]["Id"]

    cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": "fidelity", "Value": "true"}]})
    tags = cf.list_tags_for_resource(Resource=dist_arn)["Tags"]["Items"]
    values = {t["Key"]: t["Value"] for t in tags}
    assert values.get("fidelity") == "true", f"expected tag to be present, got {values}"

    cf.untag_resource(Resource=dist_arn, TagKeys={"Items": ["fidelity"]})
    tags_after = cf.list_tags_for_resource(Resource=dist_arn)["Tags"]["Items"]
    values_after = {t["Key"]: t["Value"] for t in tags_after}
    assert "fidelity" not in values_after, f"expected tag to be removed, got {values_after}"

    _force_delete_distribution(cf, dist_id)

    get_code, get_message = _error(lambda: cf.get_distribution(Id=dist_id))
    assert get_code == "NoSuchDistribution", f"expected NoSuchDistribution after delete, got {get_code}"
    assert get_message == _NO_SUCH_DISTRIBUTION, f"expected message {_NO_SUCH_DISTRIBUTION!r}, got {get_message!r}"

    tag_code, tag_message = _error(
        lambda: cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": "fidelity", "Value": "true"}]})
    )
    assert tag_code == "NoSuchResource", (
        f"expected TagResource against a deleted distribution to fail with NoSuchResource, got {tag_code}"
    )
    assert tag_message == _NO_SUCH_RESOURCE, f"expected message {_NO_SUCH_RESOURCE!r}, got {tag_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
