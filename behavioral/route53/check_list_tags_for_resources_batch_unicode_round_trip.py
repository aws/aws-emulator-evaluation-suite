"""list-tags-for-resources-batch-unicode-round-trip."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "list-tags-for-resources-batch-unicode-round-trip"
GROUP = "representation"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode tag keys/values written via ChangeTagsForResource on two different
    health checks are returned unchanged, per-resource, by a single batched
    ListTagsForResources call."""
    route53 = ctx.client("route53")

    ids = []
    for i in range(2):
        created = route53.create_health_check(
            CallerReference=f"sim2real-{uuid.uuid4()}",
            HealthCheckConfig={
                "FullyQualifiedDomainName": f"sim2real-behav-{i}.invalid",
                "Port": 80,
                "Type": "HTTP",
                "RequestInterval": 30,
                "FailureThreshold": 3,
            },
        )
        hc_id = created["HealthCheck"]["Id"]
        ids.append(hc_id)
        ctx.on_cleanup(lambda hc_id=hc_id: route53.delete_health_check(HealthCheckId=hc_id))

    expected = {
        ids[0]: {"ключ-один": "значение Ω один", "名前": "テスト 値"},
        ids[1]: {"clé-deux": "valeur é à ç", "χωρίς όνομα": "δοκιμή τιμή"},
    }
    for hc_id, tags in expected.items():
        route53.change_tags_for_resource(
            ResourceType="healthcheck",
            ResourceId=hc_id,
            AddTags=[{"Key": k, "Value": v} for k, v in tags.items()],
        )

    resp = route53.list_tags_for_resources(ResourceType="healthcheck", ResourceIds=ids)
    by_id = {s["ResourceId"]: s for s in resp["ResourceTagSets"]}
    assert set(by_id.keys()) == set(ids), (
        f"expected ResourceTagSets keyed by {sorted(ids)}, got {sorted(by_id.keys())}"
    )

    for hc_id, tags in expected.items():
        actual = {t["Key"]: t["Value"] for t in by_id[hc_id]["Tags"]}
        assert actual == tags, f"tags for {hc_id} mismatch: {actual!r} != {tags!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
