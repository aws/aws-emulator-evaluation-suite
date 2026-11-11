"""get-identity-center-auth-token-parameter-errors."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-identity-center-auth-token-parameter-errors"
GROUP = "error-semantics"
SERVICES = ["redshift"]

# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")
ADMIN_USERNAME = "s2radmin"
ADMIN_PASSWORD = "Sim2Real-Passw0rd1"
NOT_IDC_MESSAGE = "Request rejected: Not an IDC user acting"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetIdentityCenterAuthToken from a non-Identity-Center principal is refused with
    UnsupportedOperation (HTTP 400) before any ClusterIds validation: for a malformed, a
    nonexistent and an existing cluster id alike, after a positive-control read succeeds."""
    redshift = ctx.client("redshift")

    # Positive control: an ordinary read succeeds on this account/credentials.
    redshift.describe_clusters(MaxRecords=20)

    # 1. Malformed cluster identifier -- still UnsupportedOperation: the credential-type gate is
    #    checked before ClusterIds format validation.
    code, message, http_status = _error(lambda: redshift.get_identity_center_auth_token(ClusterIds=["bad-cluster-"]))
    assert code == "UnsupportedOperation", f"expected UnsupportedOperation, got {code}"
    assert message == NOT_IDC_MESSAGE, f"expected message {NOT_IDC_MESSAGE!r}, got {message!r}"
    assert http_status == 400, f"expected HTTP 400, got {http_status}"

    # 2. Well-formed but nonexistent cluster -- still UnsupportedOperation: the gate precedes
    #    existence validation too.
    missing_cluster_id = ctx.unique_name("sim2real-behav-idcmiss-")
    code, message, http_status = _error(lambda: redshift.get_identity_center_auth_token(ClusterIds=[missing_cluster_id]))
    assert code == "UnsupportedOperation", f"expected UnsupportedOperation, got {code}"
    assert message == NOT_IDC_MESSAGE, f"expected message {NOT_IDC_MESSAGE!r}, got {message!r}"
    assert http_status == 400, f"expected HTTP 400, got {http_status}"

    # 3. A real, existing cluster -- still UnsupportedOperation: not an artifact of a missing or
    #    malformed ClusterId, the gate holds for a genuinely resolvable request too.
    cluster_id = ctx.unique_name("sim2real-behav-idc-")
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))
    redshift.create_cluster(**_cluster_params(redshift, cluster_id))
    code, message, http_status = _error(lambda: redshift.get_identity_center_auth_token(ClusterIds=[cluster_id]))
    assert code == "UnsupportedOperation", f"expected UnsupportedOperation, got {code}"
    assert message == NOT_IDC_MESSAGE, f"expected message {NOT_IDC_MESSAGE!r}, got {message!r}"
    assert http_status == 400, f"expected HTTP 400, got {http_status}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return (error code, message, HTTP status). An unexpected success raises, so an
    accepted call is reported as such and not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response["Error"]["Code"],
            exc.response["Error"].get("Message"),
            exc.response["ResponseMetadata"]["HTTPStatusCode"],
        )
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _node_type(rs, cluster_type: str = "single-node") -> str:
    """Cheapest orderable node type for *cluster_type* in this region."""
    available = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = rs.describe_orderable_cluster_options(**kwargs)
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != cluster_type:
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((nt for nt in NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type} options in this region")
        chosen = sorted(available)[0]
    return chosen


def _cluster_params(rs, cluster_id: str) -> dict:
    return dict(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(rs),
        ClusterType="single-node",
        MasterUsername=ADMIN_USERNAME,
        MasterUserPassword=ADMIN_PASSWORD,
        # Encrypted at rest, as a customer would configure it.
        Encrypted=True,
    )


def _delete_cluster(rs, cluster_id: str, timeout_s: float = 240.0) -> None:
    """Teardown: a cluster still 'creating' refuses deletion with InvalidClusterState, so retry
    that every 2 s to the deadline; any other refusal raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ClusterNotFound":
                return
            if code != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
