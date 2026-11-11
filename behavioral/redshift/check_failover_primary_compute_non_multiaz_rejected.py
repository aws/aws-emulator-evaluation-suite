"""failover-primary-compute-non-multiaz-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "failover-primary-compute-non-multiaz-rejected"
GROUP = "state-machine"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FailoverPrimaryCompute on an available non-Multi-AZ cluster is rejected with InvalidClusterState
    and its exact message, the availability zone is unchanged, and ModifyCluster of the maintenance
    window on the same cluster still succeeds."""
    redshift = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-failover-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType="ra3.xlplus",
        MasterUsername="sim2realadmin",
        MasterUserPassword="Sim2RealTest1234!",
        ClusterType="single-node",
        DBName="dev",
        PubliclyAccessible=False,
        MultiAZ=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))

    before = _wait_for_status(ctx, redshift, cluster_id, "available", timeout_s=900)
    # MultiAZ is reported as the string "Enabled"/"Disabled", not a bool.
    assert before.get("MultiAZ") == "Disabled", f"expected a non-Multi-AZ cluster, got MultiAZ={before.get('MultiAZ')!r}"
    before_az = before["AvailabilityZone"]

    code, message = _error(
        lambda: redshift.failover_primary_compute(ClusterIdentifier=cluster_id)
    )
    assert code == "InvalidClusterState", f"expected InvalidClusterState, got {code!r}"
    expected = "You can't failover primary compute of your cluster now. Try again later."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the cluster's availability zone did not change.
    after = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
    assert after["AvailabilityZone"] == before_az, (
        f"expected AvailabilityZone to stay {before_az!r} after the rejected failover, "
        f"got {after['AvailabilityZone']!r}"
    )

    # positive control: an unrelated mutation on the same, healthy cluster still succeeds.
    redshift.modify_cluster(ClusterIdentifier=cluster_id, PreferredMaintenanceWindow="sun:05:00-sun:05:30")
    _wait_for_status(ctx, redshift, cluster_id, "available", timeout_s=300)
    control = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
    assert control["PreferredMaintenanceWindow"] == "sun:05:00-sun:05:30", (
        f"expected PreferredMaintenanceWindow 'sun:05:00-sun:05:30' on the healthy cluster after "
        f"the rejected failover, got {control['PreferredMaintenanceWindow']!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_for_status(ctx, redshift, cluster_id, target_status, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        if last["ClusterStatus"] == target_status:
            return last
        time.sleep(2)
    raise AssertionError(f"cluster never reached {target_status!r} (last seen: {last})")


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
