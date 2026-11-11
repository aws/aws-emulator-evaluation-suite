"""cluster-scoped-triaged-ops-not-found-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-scoped-triaged-ops-not-found-semantics"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """For a nonexistent cluster, ModifyClusterDbRevision, GetClusterCredentialsWithIAM and
    FailoverPrimaryCompute answer ClusterNotFound with exact messages, while GetIdentityCenterAuthToken
    answers UnsupportedOperation "Request rejected: Not an IDC user acting"."""
    redshift = ctx.client("redshift")
    bogus_cluster = ctx.unique_name("sim2real-nocluster-")

    not_found = f"Cluster {bogus_cluster} not found."
    ops = [
        (
            "ModifyClusterDbRevision",
            lambda: redshift.modify_cluster_db_revision(
                ClusterIdentifier=bogus_cluster, RevisionTarget="bogus-revision"
            ),
        ),
        (
            "GetClusterCredentialsWithIAM",
            lambda: redshift.get_cluster_credentials_with_iam(ClusterIdentifier=bogus_cluster),
        ),
    ]
    for name, fn in ops:
        code, message = _error(fn)
        assert code == "ClusterNotFound", f"{name}: expected ClusterNotFound, got {code}"
        assert message == not_found, f"{name}: expected message {not_found!r}, got {message!r}"

    failover_code, failover_message = _error(
        lambda: redshift.failover_primary_compute(ClusterIdentifier=bogus_cluster)
    )
    assert failover_code == "ClusterNotFound", (
        f"FailoverPrimaryCompute: expected ClusterNotFound, got {failover_code}"
    )
    expected_failover = f"Cluster not found: {bogus_cluster}"
    assert failover_message == expected_failover, (
        f"FailoverPrimaryCompute: expected message {expected_failover!r}, got {failover_message!r}"
    )

    idc_code, idc_message = _error(
        lambda: redshift.get_identity_center_auth_token(ClusterIds=[bogus_cluster])
    )
    assert idc_code == "UnsupportedOperation", (
        f"GetIdentityCenterAuthToken: expected UnsupportedOperation, got {idc_code}"
    )
    assert idc_message == "Request rejected: Not an IDC user acting", (
        f"GetIdentityCenterAuthToken: unexpected message {idc_message!r}"
    )


def _error(fn):
    """Call fn(); return (error code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
