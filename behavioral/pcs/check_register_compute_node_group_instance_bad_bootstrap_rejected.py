"""register-compute-node-group-instance-bad-bootstrap-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-compute-node-group-instance-bad-bootstrap-rejected"
GROUP = "overly-permissive"
SERVICES = ["pcs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterComputeNodeGroupInstance with a well-formed bogus clusterIdentifier and bootstrapId gets
    AccessDeniedException with its exact message and returns no bootstrap material, while ListClusters
    succeeds on the same client."""
    pcs = ctx.client("pcs")
    bogus_cluster = "pcs_" + ("3" * 20)
    bogus_bootstrap_id = ctx.unique_name("sim2real-bootstrap-not-a-real-id")

    code = None
    message = None
    response_body = None
    try:
        response_body = pcs.register_compute_node_group_instance(
            clusterIdentifier=bogus_cluster, bootstrapId=bogus_bootstrap_id
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")

    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected_message = "This API must be called from an EC2 instance."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    assert response_body is None, "RegisterComputeNodeGroupInstance unexpectedly returned bootstrap material"

    # Positive control: the same client can still perform a legitimate,
    # differently-authorized PCS call.
    resp = pcs.list_clusters(maxResults=1)
    assert isinstance(resp.get("clusters"), list), (
        f"positive control failed: ListClusters on the same client should still succeed "
        f"and return a clusters list, got {resp.get('clusters')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
