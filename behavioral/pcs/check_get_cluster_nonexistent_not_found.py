"""get-cluster-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-cluster-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["pcs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCluster on a syntactically valid but nonexistent clusterIdentifier returns
    ResourceNotFoundException with resourceId/resourceType populated, and a
    positive control (ListClusters) still works against the same client."""
    pcs = ctx.client("pcs")
    bogus_id = "pcs_" + ("0" * 20)

    code = None
    message = None
    resource_id = None
    resource_type = None
    try:
        result = pcs.get_cluster(clusterIdentifier=bogus_id)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
        # For the awsJson1_0 protocol, modeled exception members (resourceId,
        # resourceType) are surfaced as top-level keys on the response, not
        # nested under "Error".
        resource_id = e.response.get("resourceId")
        resource_type = e.response.get("resourceType")

    else:
        raise AssertionError(f"GetCluster on a nonexistent id SUCCEEDED: {result!r}")

    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = "AWS PCS couldn't find the cluster you specified."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    # The exception shape declares resourceId/resourceType as required members.
    assert resource_id == bogus_id, f"expected resourceId {bogus_id!r}, got {resource_id!r}"
    assert resource_type == "Cluster ID", f"expected resourceType 'Cluster ID', got {resource_type!r}"

    # Positive control: a plain list call against the same account/region still succeeds.
    resp = pcs.list_clusters(maxResults=1)
    clusters = resp.get("clusters")
    assert isinstance(clusters, list), f"expected ListClusters to return a list, got {clusters!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
