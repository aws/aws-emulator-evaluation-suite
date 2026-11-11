"""get-cluster-credentials-duration-seconds-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-cluster-credentials-duration-seconds-out-of-range-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetClusterCredentials rejects a DurationSeconds value outside the documented 900-3600s
    window with InvalidParameterValue, and the minimum documented duration (900s) still succeeds
    on the very same cluster (positive control)."""
    redshift = ctx.client("redshift")
    cluster = _create_available_cluster(ctx)

    code, message = _error(
        lambda: redshift.get_cluster_credentials(
            ClusterIdentifier=cluster["id"],
            DbUser="iamtestuser",
            DbName="dev",
            AutoCreate=True,
            DurationSeconds=100,  # below the documented minimum of 900
        )
    )
    assert code == "InvalidParameterValue", (
        f"DurationSeconds=100 (below the documented 900-3600s window) should be rejected with "
        f"InvalidParameterValue, got {code!r}"
    )
    expected = "Token duration must be between 900 and 3600 seconds"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the minimum documented duration is accepted on the same cluster.
    resp = redshift.get_cluster_credentials(
        ClusterIdentifier=cluster["id"],
        DbUser="iamtestuser",
        DbName="dev",
        AutoCreate=True,
        DurationSeconds=900,
    )
    assert resp["DbPassword"], f"expected a non-empty DbPassword, got {resp.get('DbPassword')!r}"
    assert resp["DbUser"], f"expected a non-empty DbUser, got {resp.get('DbUser')!r}"


# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
_NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")


def _node_type(rs, cluster_type="single-node"):
    """Cheapest orderable node type for *cluster_type* in this region/account: node type
    availability is not a fixed API constant (dc2.large is withdrawn in some accounts), so it must
    be read from DescribeOrderableClusterOptions rather than pinned."""
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
    chosen = next((nt for nt in _NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type} options in this region")
        chosen = sorted(available)[0]
    return chosen


def _create_available_cluster(ctx) -> dict:
    redshift = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-rs-").lower()
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(redshift),
        MasterUsername="adminuser",
        MasterUserPassword="TestPassw0rd123",
        DBName="dev",
        ClusterType="single-node",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True))
    waiter = redshift.get_waiter("cluster_available")
    waiter.wait(ClusterIdentifier=cluster_id, WaiterConfig={"Delay": 2, "MaxAttempts": 600})
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    arn = f"arn:aws:redshift:{ctx.region}:{account_id}:cluster:{cluster_id}"
    return {"id": cluster_id, "arn": arn}


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises, because
    an over-permissive target accepting input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
