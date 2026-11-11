"""tag-unicode-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tag keys/values containing unicode characters attached to a WebACL via TagResource
    are returned unchanged by ListTagsForResource, and cleanly removed by UntagResource --
    distinct from the reserved-prefix rejection check."""
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    name = ctx.unique_name("sim2real-behav-webacl-tag-")

    created = wafv2.create_web_acl(
        Name=name,
        Scope=scope,
        DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility_config("tagaclmetric"),
    )
    web_acl_id = created["Summary"]["Id"]
    arn = created["Summary"]["ARN"]
    ctx.on_cleanup(lambda: wafv2.delete_web_acl(
        Name=name, Scope=scope, Id=web_acl_id,
        LockToken=wafv2.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)["LockToken"],
    ))

    tag_key = "\u90e8\u9580"  # "部門" (department)
    tag_value = "caf\u00e9-m\u00fcnchen"  # "café-münchen"

    wafv2.tag_resource(ResourceARN=arn, Tags=[{"Key": tag_key, "Value": tag_value}])

    tags = wafv2.list_tags_for_resource(ResourceARN=arn)["TagInfoForResource"]["TagList"]
    assert {"Key": tag_key, "Value": tag_value} in tags

    wafv2.untag_resource(ResourceARN=arn, TagKeys=[tag_key])

    tags2 = wafv2.list_tags_for_resource(ResourceARN=arn)["TagInfoForResource"]["TagList"]
    assert all(t["Key"] != tag_key for t in tags2)


def _visibility_config(metric_name: str) -> dict:
    return {
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": metric_name,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
