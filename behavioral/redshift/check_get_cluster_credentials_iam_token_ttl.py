"""get-cluster-credentials-iam-token-ttl."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

import secrets
import string
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "get-cluster-credentials-iam-token-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetClusterCredentials and GetClusterCredentialsWithIAM return an Expiration within tolerance of
    now + the requested DurationSeconds (1200), so the TTL is request-bound, not a fixed constant.
    """
    redshift = ctx.client("redshift")
    cid = _create_cluster(ctx, redshift)

    duration = 1200
    before = datetime.now(timezone.utc)
    creds = redshift.get_cluster_credentials(
        ClusterIdentifier=cid,
        DbUser="s2rtestuser",
        DurationSeconds=duration,
        AutoCreate=True,
    )
    after = datetime.now(timezone.utc)
    assert creds["DbPassword"], f"expected a non-empty DbPassword, got {creds.get('DbPassword')!r}"
    delta_low = (creds["Expiration"] - after).total_seconds()
    delta_high = (creds["Expiration"] - before).total_seconds()
    # Allow generous clock/network tolerance while still proving the bound is the
    # requested duration and not some unrelated fixed value (e.g. the 900s default).
    assert duration - 60 <= delta_low <= duration + 60, delta_low
    assert duration - 60 <= delta_high <= duration + 60, delta_high

    before_iam = datetime.now(timezone.utc)
    iam_creds = redshift.get_cluster_credentials_with_iam(
        ClusterIdentifier=cid,
        DurationSeconds=duration,
    )
    after_iam = datetime.now(timezone.utc)
    assert iam_creds["DbPassword"], f"expected a non-empty DbPassword, got {iam_creds.get('DbPassword')!r}"
    delta_iam_low = (iam_creds["Expiration"] - after_iam).total_seconds()
    delta_iam_high = (iam_creds["Expiration"] - before_iam).total_seconds()
    assert duration - 60 <= delta_iam_low <= duration + 60, delta_iam_low
    assert duration - 60 <= delta_iam_high <= duration + 60, delta_iam_high


# ===== helpers =====
def _strong_password() -> str:
    body = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    return f"S2r9{body}x"


# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
_NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")


def _node_type(redshift, cluster_type: str = "single-node") -> str:
    """Cheapest orderable node type for *cluster_type* in this region/account: node type
    availability is not a fixed API constant (dc2.large is withdrawn in some accounts), so it must
    be read from DescribeOrderableClusterOptions rather than pinned."""
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
        assert available, f"no orderable {cluster_type} options in this region"
        chosen = sorted(available)[0]
    return chosen


def _create_cluster(ctx, redshift) -> str:
    cid = ctx.unique_name("sim2real-rsttl-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cid,
        NodeType=_node_type(redshift),
        ClusterType="single-node",
        MasterUsername="s2radmin",
        MasterUserPassword=_strong_password(),
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=subnet_group,
    )

    def _cleanup() -> None:
        # Retry InvalidClusterState (still creating/modifying) to a deadline; done once the
        # delete is accepted, the cluster is gone, or it is already deleting.
        deadline = time.monotonic() + 900.0
        while True:
            try:
                redshift.delete_cluster(ClusterIdentifier=cid, SkipFinalClusterSnapshot=True)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in ("ClusterNotFound", "ClusterNotFoundFault"):
                    return
                if code != "InvalidClusterState":
                    raise
            try:
                status = redshift.describe_clusters(ClusterIdentifier=cid)["Clusters"][0]["ClusterStatus"]
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") in ("ClusterNotFound", "ClusterNotFoundFault"):
                    return
                raise
            if status == "deleting":
                return
            if time.monotonic() >= deadline:
                raise AssertionError(f"cluster {cid} still {status!r}, not deletable after 900s")
            time.sleep(2)

    ctx.on_cleanup(_cleanup)
    waiter = redshift.get_waiter("cluster_available")
    waiter.wait(ClusterIdentifier=cid, WaiterConfig={"Delay": 2, "MaxAttempts": 900})
    return cid


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
            ("ClusterSubnetGroupNotFoundFault",), timeout_s=900.0, interval_s=2.0,
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
