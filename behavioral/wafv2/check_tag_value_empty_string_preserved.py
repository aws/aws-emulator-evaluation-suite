"""tag-value-empty-string-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-empty-string-preserved"
GROUP = "representation"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag written with an empty-string value is preserved as an empty string
    (not omitted from the tag list, not coerced to null) when listed back."""
    wafv2 = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-ipset-tagempty-")
    created = wafv2.create_ip_set(
        Name=name,
        Scope="REGIONAL",
        IPAddressVersion="IPV4",
        Addresses=["203.0.113.0/24"],
    )["Summary"]
    ip_set_id = created["Id"]
    arn = created["ARN"]

    def _cleanup():
        current = wafv2.get_ip_set(Name=name, Scope="REGIONAL", Id=ip_set_id)
        wafv2.delete_ip_set(
            Name=name, Scope="REGIONAL", Id=ip_set_id, LockToken=current["LockToken"]
        )

    ctx.on_cleanup(_cleanup)

    wafv2.tag_resource(ResourceARN=arn, Tags=[{"Key": "Environment", "Value": ""}])

    tags = wafv2.list_tags_for_resource(ResourceARN=arn)["TagInfoForResource"]["TagList"]
    matching = [t for t in tags if t["Key"] == "Environment"]
    assert len(matching) == 1, f"expected exactly one 'Environment' tag, got {tags}"
    assert matching[0]["Value"] == "", (
        f"expected the empty-string tag value to be preserved, got {matching[0]['Value']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
