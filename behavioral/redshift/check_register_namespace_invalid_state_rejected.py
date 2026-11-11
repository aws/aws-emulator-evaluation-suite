"""register-namespace-invalid-state-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-namespace-invalid-state-rejected"
GROUP = "state-machine"
SERVICES = ["redshift"]

# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterNamespace on a cluster that is not yet available is rejected with InvalidParameterValue
    and its exact message, and the same call succeeds once the cluster is available."""
    redshift = ctx.client("redshift")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    cluster_id = ctx.unique_name("sim2real-regns-")
    namespace_id = {"ProvisionedIdentifier": {"ClusterIdentifier": cluster_id}}
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(redshift),
        MasterUsername="sim2realadmin",
        MasterUserPassword="Sim2RealTest1234!",
        ClusterType="single-node",
        DBName="dev",
        PubliclyAccessible=False,
        Encrypted=True,
        Tags=[{"Key": "sim2real-behavioral", "Value": CHECK}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))

    def _register():
        return redshift.register_namespace(
            NamespaceIdentifier=namespace_id,
            ConsumerIdentifiers=[account_id],
        )

    def _best_effort_deregister():
        from botocore.exceptions import ClientError

        try:
            redshift.deregister_namespace(
                NamespaceIdentifier=namespace_id, ConsumerIdentifiers=[account_id]
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFound":
                raise

    # Immediately after CreateCluster the cluster is still in the `creating` transition.
    status_now = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
        "ClusterStatus"
    ]
    assert status_now != "available", f"cluster unexpectedly already available: {status_now}"

    code, message = _error_code_and_message(_register)
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}: {message}"
    expected_message = (
        "This cluster version doesn't support Register Namespace operation. "
        "Please upgrade to the latest cluster version."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    _wait_for_status(ctx, redshift, cluster_id, "available", timeout_s=900)

    # positive control: the identical call succeeds once the cluster is available --
    # proving the earlier rejection was the state guard, not a broken client/cluster.
    result = _register()
    assert result["Status"] in ("Registering", "Registered"), result["Status"]
    ctx.on_cleanup(_best_effort_deregister)

    # Independent-operation terminal read: DescribeClusters (not RegisterNamespace) confirms the
    # cluster recovers to `available` after the registration was accepted. RegisterNamespace is
    # not a no-op here -- real AWS drives the cluster through a transient `modifying` state before
    # it settles, which a bounded wait (not an instant snapshot) is required to observe correctly.
    _wait_for_status(ctx, redshift, cluster_id, "available", timeout_s=180)


def _node_type(rs, cluster_type="single-node"):
    """Cheapest orderable node type for *cluster_type* in this account/region -- this account's
    entitlements vary, and a hardcoded literal (e.g. dc2.large) can be InvalidParameterValue here
    even though the model has no enum constraint on it."""
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


def _error_code(fn):
    return _error_code_and_message(fn)[0]


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_for_status(ctx, redshift, cluster_id, target_status, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
            "ClusterStatus"
        ]
        if last == target_status:
            return
        time.sleep(2)
    raise AssertionError(f"cluster never reached {target_status!r} (last seen: {last!r})")


def _delete_cluster(redshift, cluster_id):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code == "InvalidClusterState":
                time.sleep(15)
                continue
            raise
    raise AssertionError(f"could not delete cluster {cluster_id} within retry budget")


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
