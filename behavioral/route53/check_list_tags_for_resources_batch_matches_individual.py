"""list-tags-for-resources-batch-matches-individual."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "list-tags-for-resources-batch-matches-individual"
GROUP = "server-side"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Batch ListTagsForResources across two health checks returns the same tag sets,
    keyed per resource id, as individual ListTagsForResource calls."""
    r53 = ctx.client("route53")

    hc_ids = [_create_health_check(ctx, r53) for _ in range(2)]
    tag_sets = [
        [{"Key": "sim2real-env", "Value": "alpha"}, {"Key": "sim2real-owner", "Value": "team-a"}],
        [{"Key": "sim2real-env", "Value": "beta"}],
    ]
    for hc_id, tags_ in zip(hc_ids, tag_sets):
        r53.change_tags_for_resource(
            ResourceType="healthcheck", ResourceId=hc_id, AddTags=tags_
        )

    individual = {}
    for hc_id in hc_ids:
        resp = r53.list_tags_for_resource(ResourceType="healthcheck", ResourceId=hc_id)
        individual[hc_id] = _tag_dict(resp["ResourceTagSet"]["Tags"])

    batch = r53.list_tags_for_resources(ResourceType="healthcheck", ResourceIds=hc_ids)
    batch_by_id = {
        rts["ResourceId"]: _tag_dict(rts["Tags"]) for rts in batch["ResourceTagSets"]
    }

    assert set(batch_by_id.keys()) == set(individual.keys()), (
        f"batch returned resource ids {sorted(batch_by_id.keys())}, "
        f"expected {sorted(individual.keys())}"
    )
    for hc_id in hc_ids:
        assert batch_by_id[hc_id] == individual[hc_id], (hc_id, batch_by_id[hc_id], individual[hc_id])
    # Sanity: the two health checks really do have distinct tag sets.
    assert individual[hc_ids[0]] != individual[hc_ids[1]], (
        f"expected distinct tag sets, both are {individual[hc_ids[0]]!r}"
    )


def _tag_dict(tags_list):
    return {t["Key"]: t["Value"] for t in tags_list}


def _create_health_check(ctx, r53):
    resp = r53.create_health_check(
        CallerReference=f"sim2real-{uuid.uuid4()}",
        HealthCheckConfig={
            "FullyQualifiedDomainName": "sim2real-hc-target.invalid",
            "Port": 80,
            "Type": "HTTP",
            "ResourcePath": "/",
            "RequestInterval": 30,
            "FailureThreshold": 3,
        },
    )
    hc_id = resp["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda: r53.delete_health_check(HealthCheckId=hc_id))
    return hc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
