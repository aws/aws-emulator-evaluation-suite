"""distribution-with-tags-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

MANAGED_CACHING_OPTIMIZED_CACHE_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"

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

def _minimal_distribution_config(name, **overrides):
    origin_domain = f"{name}.s3.amazonaws.com"
    config = {
        "CallerReference": name,
        "Comment": name,
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": origin_domain,
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_OPTIMIZED_CACHE_POLICY_ID,
        },
    }
    config.update(overrides)
    return config

CHECK = "distribution-with-tags-lifecycle"
GROUP = 'tagging'
SERVICES = ['cloudfront']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A distribution created via CreateDistributionWithTags is retrievable via
    ListTagsForResource, and its tags are mutable via TagResource/UntagResource."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-dist-tag-")
    tag_key = "sim2real-behav-tagkey"
    create_resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": _minimal_distribution_config(name),
            "Tags": {"Items": [{"Key": tag_key, "Value": "v1"}]},
        }
    )
    dist_id = create_resp["Distribution"]["Id"]
    arn = create_resp["Distribution"]["ARN"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    status = create_resp["Distribution"]["Status"]
    assert status in ("InProgress", "Deployed"), f"expected InProgress or Deployed after create, got {status}"

    listed = cf.list_tags_for_resource(Resource=arn)
    tag_map = {t["Key"]: t.get("Value") for t in listed["Tags"]["Items"]}
    assert tag_map.get(tag_key) == "v1", f"expected tag {tag_key}=v1 from creation, got {tag_map}"

    cf.tag_resource(Resource=arn, Tags={"Items": [{"Key": tag_key, "Value": "v2"}]})
    listed2 = cf.list_tags_for_resource(Resource=arn)
    tag_map2 = {t["Key"]: t.get("Value") for t in listed2["Tags"]["Items"]}
    assert tag_map2.get(tag_key) == "v2", f"expected TagResource to update to v2, got {tag_map2}"

    cf.untag_resource(Resource=arn, TagKeys={"Items": [tag_key]})
    listed3 = cf.list_tags_for_resource(Resource=arn)
    tag_map3 = {t["Key"]: t.get("Value") for t in listed3["Tags"]["Items"]}
    assert tag_key not in tag_map3, f"expected tag removed by UntagResource, still present: {tag_map3}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
