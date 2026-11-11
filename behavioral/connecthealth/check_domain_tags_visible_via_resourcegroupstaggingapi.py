"""domain-tags-visible-via-resourcegroupstaggingapi."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-tags-visible-via-resourcegroupstaggingapi"
GROUP = "cross-service"
SERVICES = ["connecthealth"]


def _create_domain(ch, name, **extra):
    # Kept well under the check's 300s body budget: other Domains in the account can briefly hold
    # the Domain cap, so retrying on a transient Domain-count quota is legitimate, but retrying for
    # the full body budget leaves no room for the RGT propagation wait below and turns a clean
    # quota-exceeded raise into a timeout instead.
    deadline = time.monotonic() + 120.0
    while True:
        try:
            return ch.create_domain(name=name, **extra)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code not in ("ServiceQuotaExceededException", "ValidationException") or "maximum limit" not in msg:
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5.0)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Domain tagged via connecthealth TagResource is discoverable cross-service through the Resource Groups
    Tagging API's GetResources, and disappears from that index once UntagResource removes the tag."""
    ch = ctx.client("connecthealth")
    tag_value = ctx.unique_name("sim2real-conh-tagval-")
    resp = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"))
    domain_id = resp["domainId"]
    arn = resp["arn"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))

    ch.tag_resource(resourceArn=arn, tags={"sim2real-probe": tag_value})
    own_tags = ch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert own_tags == {"sim2real-probe": tag_value}, f"expected just-written tag, connecthealth reports {own_tags!r}"

    rgt = ctx.client("resourcegroupstaggingapi")

    def _find_via_rgt():
        page = rgt.get_resources(
            TagFilters=[{"Key": "sim2real-probe", "Values": [tag_value]}],
            ResourceTypeFilters=["health-agent"],
        )
        for r in page.get("ResourceTagMappingList", []):
            if r["ResourceARN"] == arn:
                return r
        return None

    appear_start = time.monotonic()
    appear_deadline = appear_start + 60.0
    found = None
    while time.monotonic() < appear_deadline:
        found = _find_via_rgt()
        if found is not None:
            break
        time.sleep(3.0)
    appear_latency = time.monotonic() - appear_start
    assert found is not None, "tagged Domain never appeared via ResourceGroupsTaggingAPI within 60s"
    tag_map = {t["Key"]: t["Value"] for t in found["Tags"]}
    assert tag_map.get("sim2real-probe") == tag_value, (
        f"RGT-reported tag value mismatch: expected {tag_value!r}, got {tag_map.get('sim2real-probe')!r}"
    )

    # negative/effect, at the consumer: untag, then prove absence through the SAME cross-service read
    # that proved presence above (RGT is what this check exists to validate; the connecthealth-side
    # read is a producer-side sanity check, not the terminal assertion). Absence is held for >= 3x the
    # appearance latency just measured on this same wiring in this same run, so a target that is merely
    # slower to propagate than this run's observed L does not get scored as having blocked the removal.
    ch.untag_resource(resourceArn=arn, tagKeys=["sim2real-probe"])
    own_tags_after = ch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert own_tags_after == {}, f"expected no tags after UntagResource, connecthealth still reports {own_tags_after!r}"

    absence_window = min(max(3.0 * appear_latency, 15.0), 90.0)
    absence_deadline = time.monotonic() + absence_window
    while time.monotonic() < absence_deadline:
        reappeared = _find_via_rgt()
        assert reappeared is None, f"untagged Domain still visible via ResourceGroupsTaggingAPI: {reappeared!r}"
        time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

