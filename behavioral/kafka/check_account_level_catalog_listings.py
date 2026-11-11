"""account-level-catalog-listings."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "account-level-catalog-listings"
GROUP = 'read-paths'
SERVICES = ['kafka']


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListKafkaVersions returns versions with at least one ACTIVE, every ARN ListClusters (v1) returns is
    PROVISIONED in ListClustersV2, and the replicator, VPC-connection and configuration listings return
    lists."""
    kafka = ctx.client("kafka")
    versions = kafka.list_kafka_versions()["KafkaVersions"]
    assert versions, "ListKafkaVersions returned no versions"
    assert all(v.get("Version") for v in versions), versions[:3]
    assert any(v.get("Status") == "ACTIVE" for v in versions), versions[:3]

    v2_types: dict[str, str] = {}
    for page in kafka.get_paginator("list_clusters_v2").paginate():
        for cluster in page.get("ClusterInfoList", []):
            v2_types[cluster["ClusterArn"]] = cluster.get("ClusterType", "")

    v1_arns: set[str] = set()
    for page in kafka.get_paginator("list_clusters").paginate():
        for cluster in page.get("ClusterInfoList", []):
            v1_arns.add(cluster["ClusterArn"])

    # Only compare ARNs both views agree exist; the account is shared, so a
    # cluster can appear/disappear between the two paginations.
    for arn in v1_arns & set(v2_types):
        assert v2_types[arn] == "PROVISIONED", (
            f"ListClusters reported {arn} which ListClustersV2 types as "
            f"{v2_types[arn]!r}; the v1 view is PROVISIONED-only"
        )

    for op_name, method, key in (
        ("ListReplicators", "list_replicators", "Replicators"),
        ("ListVpcConnections", "list_vpc_connections", "VpcConnections"),
        ("ListConfigurations", "list_configurations", "Configurations"),
    ):
        result = getattr(kafka, method)()
        assert isinstance(result.get(key), list), f"{op_name} response missing {key!r}: {result}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
