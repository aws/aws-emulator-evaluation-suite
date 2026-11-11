"""modify-aqua-configuration-unsupported-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-aqua-configuration-unsupported-rejected"
GROUP = "overly-permissive"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyAquaConfiguration, a retired operation, fails with InternalFailure and its exact message
    for a nonexistent cluster rather than 200 OK, DescribeClusters answers ClusterNotFound for it,
    and DescribeClusterVersions still succeeds."""
    redshift = ctx.client("redshift")
    nonexistent_cluster_id = ctx.unique_name("sim2real-noaqua-")

    code, message = _error(
        lambda: redshift.modify_aqua_configuration(
            ClusterIdentifier=nonexistent_cluster_id, AquaConfigurationStatus="enabled"
        )
    )
    assert code == "InternalFailure", code
    assert message == (
        "An internal error has occurred. Please try your query again at a later time."
    ), f"unexpected InternalFailure message {message!r}"

    # effect absent: no cluster (and so no AQUA/reserved state) exists under that identifier.
    describe_code, describe_message = _error(
        lambda: redshift.describe_clusters(ClusterIdentifier=nonexistent_cluster_id)
    )
    assert describe_code == "ClusterNotFound", describe_code
    assert describe_message == f"Cluster {nonexistent_cluster_id} not found.", (
        f"unexpected ClusterNotFound message {describe_message!r}"
    )

    # positive control: a read-only, cluster-independent call still succeeds -- proving the
    # rejection above is specific to the nonexistent cluster, not a broken client/credentials.
    versions = redshift.describe_cluster_versions()
    assert "ClusterVersions" in versions, versions


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
