"""get-cluster-credentials-with-iam-unsupported-rejected."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-cluster-credentials-with-iam-unsupported-rejected"
GROUP = "overly-permissive"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetClusterCredentialsWithIAM scoped to a CustomDomainName no cluster uses is rejected with
    InvalidParameterValue "To use get credentials, you must provide an active custom domain name.",
    while the unscoped call on the same cluster succeeds before and after."""
    redshift = ctx.client("redshift")
    cluster_id = _create_available_cluster(ctx, "iamcred")

    # Positive control: plain credential retrieval against a healthy, available
    # cluster succeeds and returns real, usable-looking credential fields.
    creds = redshift.get_cluster_credentials_with_iam(ClusterIdentifier=cluster_id)
    assert creds.get("DbUser"), "expected a non-empty DbUser in the response"
    assert creds.get("DbPassword"), "expected a non-empty DbPassword in the response"
    assert "Expiration" in creds, "expected an Expiration timestamp in the response"

    # Break exactly one thing: scope the credential request to a custom domain
    # name that has never been associated with this cluster.
    unassociated_domain = f"{ctx.unique_name('sim2real-behav-nodomain-')}.example.com"
    code, message = _error(
        lambda: redshift.get_cluster_credentials_with_iam(
            ClusterIdentifier=cluster_id, CustomDomainName=unassociated_domain
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    expected = "To use get credentials, you must provide an active custom domain name."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent / no side effect: the plain (unscoped) path still works
    # identically after the rejected custom-domain request, proving the
    # cluster's normal credential path was not disturbed by the rejection.
    creds_after = redshift.get_cluster_credentials_with_iam(ClusterIdentifier=cluster_id)
    assert creds_after.get("DbUser"), "expected credential retrieval to keep working after the rejection"


def _error(fn):
    """Call fn(); return (code, message) of its botocore error. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _random_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(12))


# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")


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


def _create_available_cluster(ctx, tag: str) -> str:
    redshift = ctx.client("redshift")
    cluster_id = ctx.unique_name(f"sim2real-behav-{tag}-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(redshift),
        ClusterType="single-node",
        MasterUsername="s2radmin",
        MasterUserPassword=_random_password(),
        DBName="dev",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": cluster_id}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
    )
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=1200.0)
    return cluster_id


def _wait_cluster_status(
    ctx, cluster_id: str, want: str, timeout_s: float = 1200.0, interval_s: float = 15.0
) -> None:
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        clusters = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"]
        last = clusters[0]["ClusterStatus"] if clusters else None
        if last == want:
            return
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} never reached {want!r} (last={last!r}) in {timeout_s}s")


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
