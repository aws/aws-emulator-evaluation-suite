"""list-rules-filters-by-resource-type."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-rules-filters-by-resource-type"
GROUP = "lifecycle"
SERVICES = ["rbin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRules(ResourceType=X) only returns rules for that resource type, even when
    rules for other resource types exist."""
    rbin = ctx.client("rbin")

    snapshot_id = rbin.create_rule(
        ResourceType="EBS_SNAPSHOT",
        RetentionPeriod={"RetentionPeriodValue": 4, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-typefilter-snap-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Identifier"]
    ctx.on_cleanup(lambda: rbin.delete_rule(Identifier=snapshot_id))

    image_id = rbin.create_rule(
        ResourceType="EC2_IMAGE",
        RetentionPeriod={"RetentionPeriodValue": 4, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-typefilter-image-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Identifier"]
    ctx.on_cleanup(lambda: rbin.delete_rule(Identifier=image_id))

    snapshot_ids = _list_all_ids(rbin, "EBS_SNAPSHOT")
    image_ids = _list_all_ids(rbin, "EC2_IMAGE")

    assert snapshot_id in snapshot_ids, f"EBS_SNAPSHOT rule {snapshot_id} missing from ListRules(ResourceType=EBS_SNAPSHOT): {snapshot_ids}"
    assert snapshot_id not in image_ids, f"EBS_SNAPSHOT rule {snapshot_id} leaked into ListRules(ResourceType=EC2_IMAGE): {image_ids}"
    assert image_id in image_ids, f"EC2_IMAGE rule {image_id} missing from ListRules(ResourceType=EC2_IMAGE): {image_ids}"
    assert image_id not in snapshot_ids, f"EC2_IMAGE rule {image_id} leaked into ListRules(ResourceType=EBS_SNAPSHOT): {snapshot_ids}"


def _list_all_ids(rbin, resource_type: str) -> set[str]:
    ids: set[str] = set()
    token = None
    while True:
        kwargs = {"ResourceType": resource_type}
        if token:
            kwargs["NextToken"] = token
        resp = rbin.list_rules(**kwargs)
        ids.update(r["Identifier"] for r in resp.get("Rules", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
