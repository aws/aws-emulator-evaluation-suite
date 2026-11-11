"""identity-center-auth-token-ttl."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-center-auth-token-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["redshift"]

_NOT_IDC_MESSAGE = "Request rejected: Not an IDC user acting"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetIdentityCenterAuthToken rejects a plain-IAM caller with UnsupportedOperation and the same
    exact message both while the cluster is not yet 'available' and after it is: the credential
    gate fires before any cluster-state check."""
    redshift = ctx.client("redshift")

    # Positive control: plain IAM credentials are otherwise fully functional against the
    # Redshift control plane, isolating the rejections below to the specific preconditions
    # under test rather than a general credentials/connectivity failure.
    redshift.describe_clusters(MaxRecords=20)

    cid = ctx.unique_name("sim2real-idctok-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cid,
        NodeType=_node_type(redshift),
        ClusterType="single-node",
        MasterUsername="s2radmin",
        MasterUserPassword=_strong_password(),
        PubliclyAccessible=False,
        # Encrypted at rest, as a customer would configure it; RA3 node types refuse retention 0.
        Encrypted=True,
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real", "Value": "identity-center-auth-token-ttl"}],
        ClusterSubnetGroupName=subnet_group,
    )

    def _cleanup() -> None:
        # By the time this runs, the body below has already waited for 'available' on the
        # success path, so this is a fast, direct delete. A best-effort fallback (never a
        # long exploratory wait -- that belongs in the body, not the 60s cleanup budget) for
        # the case where an earlier assertion raised while the cluster was still transitioning.
        try:
            redshift.delete_cluster(ClusterIdentifier=cid, SkipFinalClusterSnapshot=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFound":
                raise

    ctx.on_cleanup(_cleanup)

    # The cluster was just requested and cannot possibly be 'available' yet.
    status = redshift.describe_clusters(ClusterIdentifier=cid)["Clusters"][0]["ClusterStatus"]
    assert status != "available", f"cluster unexpectedly already available: {status}"

    code, message = _error(lambda: redshift.get_identity_center_auth_token(ClusterIds=[cid]))
    assert code == "UnsupportedOperation", (
        f"expected the credential-type gate (UnsupportedOperation) even for a cluster still "
        f"in {status!r}, got {code!r}"
    )
    assert message == _NOT_IDC_MESSAGE, f"unexpected UnsupportedOperation message {message!r}"

    # Consistency leg: the same call against the SAME cluster once it reaches 'available' must
    # get the IDENTICAL code -- if cluster state were the real gate, this would now succeed (or
    # fail differently); getting the same UnsupportedOperation proves state was never the gate.
    available_status = _wait_for_available(redshift, cid, timeout_s=250.0)
    code_after, message_after = _error(
        lambda: redshift.get_identity_center_auth_token(ClusterIds=[cid])
    )
    assert code_after == "UnsupportedOperation", (
        f"expected the same credential-type gate once available (status={available_status}), "
        f"got {code_after!r}"
    )
    assert message_after == _NOT_IDC_MESSAGE, (
        f"unexpected UnsupportedOperation message once available {message_after!r}"
    )


# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
_NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")


def _node_type(redshift, cluster_type: str = "single-node") -> str:
    """Cheapest orderable node type for *cluster_type* in this region/account: dc2.large is
    not orderable in every account, so this discovers what actually is rather than assuming."""
    available: list[str] = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = redshift.describe_orderable_cluster_options(**kwargs)
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != cluster_type:
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((nt for nt in _NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type} options in this region")
        chosen = sorted(available)[0]
    return chosen


def _strong_password() -> str:
    body = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    return f"S2r9{body}x"


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_available(redshift, cid: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = redshift.describe_clusters(ClusterIdentifier=cid)["Clusters"][0]["ClusterStatus"]
        if status == "available":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cid} did not reach available within {timeout_s}s")


def _network_redshift_subnet_group(ctx, client) -> str:
    """A Redshift cluster subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-rsg-")
    client.create_cluster_subnet_group(
        ClusterSubnetGroupName=name,
        Description="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cluster_subnet_group(ClusterSubnetGroupName=name),
            ("InvalidClusterSubnetGroupStateFault", "ClusterSubnetGroupInUse"),
            ("ClusterSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
