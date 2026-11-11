"""replication-configuration-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "replication-configuration-lifecycle"
GROUP = 'registry-config'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-replication")
def run(ctx) -> None:
    """PutReplicationConfiguration is reflected by DescribeRegistry, and restoring the
    original configuration leaves the prior rule set intact — the registry replication
    config is a read-your-write singleton."""
    ecr = ctx.client("ecr")
    registry_id = ecr.describe_registry()["registryId"]
    region = ctx.region
    # A replication destination must differ from the source region; these two literals are an
    # arbitrary distinct pair, not a pin to a specific region.
    dest_region = "us-east-2" if region != "us-east-2" else "us-east-1"

    original = ecr.describe_registry().get("replicationConfiguration", {})
    original_rules = original.get("rules", [])

    try:
        put = ecr.put_replication_configuration(
            replicationConfiguration={
                "rules": [
                    {
                        "destinations": [
                            {"region": dest_region, "registryId": registry_id}
                        ]
                    }
                ]
            }
        )
        assert put["replicationConfiguration"]["rules"][0]["destinations"][0][
            "region"
        ] == dest_region, put

        desc = ecr.describe_registry()
        assert desc["registryId"] == registry_id, (registry_id, desc)
        rules = desc["replicationConfiguration"]["rules"]
        assert len(rules) == 1, rules
        assert rules[0]["destinations"][0]["region"] == dest_region, rules
    finally:
        ecr.put_replication_configuration(
            replicationConfiguration={"rules": original_rules}
        )

    after = ecr.describe_registry()["replicationConfiguration"]["rules"]
    assert after == original_rules, after

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
