"""list-tags-for-resources-batch-order-preserved."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "list-tags-for-resources-batch-order-preserved"
GROUP = "ordering"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Batched ListTagsForResources returns exactly one ResourceTagSet per requested id, each
    self-identified by its ResourceId; Route 53 guarantees no order, so entries are matched by id."""
    route53 = ctx.client("route53")

    zone_ids: list[str] = []
    for i in range(3):
        full_id = route53.create_hosted_zone(
            Name=f"{ctx.unique_name('sim2real-behav-')}-{i}.zone-order-test.com",
            CallerReference=str(uuid.uuid4()),
        )["HostedZone"]["Id"]
        zone_id = _zone_id(full_id)
        ctx.on_cleanup(lambda z=full_id: route53.delete_hosted_zone(Id=z))
        route53.change_tags_for_resource(
            ResourceType="hostedzone",
            ResourceId=zone_id,
            AddTags=[{"Key": "batch-index", "Value": str(i)}],
        )
        zone_ids.append(zone_id)

    # Request in a scrambled order distinct from creation order.
    requested_order = [zone_ids[2], zone_ids[0], zone_ids[1]]
    resp = route53.list_tags_for_resources(
        ResourceType="hostedzone", ResourceIds=requested_order
    )
    returned_order = [s["ResourceId"] for s in resp["ResourceTagSets"]]

    assert sorted(returned_order) == sorted(requested_order), (
        f"expected the same set of ids {sorted(requested_order)}, "
        f"got {sorted(returned_order)}"
    )

    by_id = {s["ResourceId"]: s["Tags"] for s in resp["ResourceTagSets"]}
    for i, zid in enumerate(zone_ids):
        tags = {t["Key"]: t["Value"] for t in by_id[zid]}
        assert tags.get("batch-index") == str(i), f"zone {zid} has wrong tags: {tags}"


def _zone_id(full_id: str) -> str:
    return full_id.rsplit("/", 1)[-1]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
