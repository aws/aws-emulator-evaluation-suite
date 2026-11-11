"""e2e-resource-policy-access-enforcement-flow."""
from __future__ import annotations

import json
import secrets
import string
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-resource-policy-access-enforcement-flow"
GROUP = "e2e"
SERVICES = ["redshift"]


_UNSUPPORTED_CLUSTER = (
    "Resource type cluster isn't supported for the resource policy. Choose another resource type."
)
_UNSUPPORTED_SNAPSHOT = (
    "Resource type snapshot isn't supported for the resource policy. Choose another resource type."
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Put/GetResourcePolicy reject both a provisioned-cluster ARN and a cluster-snapshot ARN with
    InvalidParameterValue and the exact unsupported-resource-type message, while the cluster and
    snapshot stay describable by their owner."""
    redshift = ctx.client("redshift")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    other_account = "111122223333"

    cluster_id = _create_available_cluster(ctx, redshift)
    cluster_arn = f"arn:aws:redshift:{region}:{account_id}:cluster:{cluster_id}"

    # Positive control: the account and its Redshift credentials are healthy --
    # the owner can describe what it just created.
    cluster = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
    assert cluster["ClusterIdentifier"] == cluster_id, (
        f"expected owner describe to see {cluster_id!r}, got {cluster!r}"
    )

    cluster_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowConsumerDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{other_account}:root"},
                "Action": "redshift:DescribeClusters",
                "Resource": cluster_arn,
            }
        ],
    }
    cluster_error = _client_error(lambda: redshift.put_resource_policy(ResourceArn=cluster_arn, Policy=json.dumps(cluster_policy)))
    assert cluster_error["Code"] == "InvalidParameterValue", (
        f"expected PutResourcePolicy on a cluster ARN to be refused with InvalidParameterValue, got {cluster_error!r}"
    )
    assert cluster_error["Message"] == _UNSUPPORTED_CLUSTER, (
        f"expected the refusal to name the unsupported resource type, got message: {cluster_error['Message']!r}"
    )
    # Independent read (a different operation, GetResourcePolicy) corroborates: the
    # cluster resource type itself is unsupported, not merely lacking a policy.
    get_cluster_error = _client_error(lambda: redshift.get_resource_policy(ResourceArn=cluster_arn))
    assert get_cluster_error["Code"] == "InvalidParameterValue", (
        f"expected GetResourcePolicy on a cluster ARN to be refused with InvalidParameterValue too, got {get_cluster_error!r}"
    )
    assert get_cluster_error["Message"] == _UNSUPPORTED_CLUSTER, (
        f"expected the refusal to name the unsupported resource type, got message: {get_cluster_error['Message']!r}"
    )

    snapshot_id = ctx.unique_name("sim2real-snap-").lower().replace("_", "-")
    redshift.create_cluster_snapshot(
        SnapshotIdentifier=snapshot_id,
        ClusterIdentifier=cluster_id,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_snapshot(redshift, snapshot_id))
    _poll_until(
        probe=lambda: redshift.describe_cluster_snapshots(SnapshotIdentifier=snapshot_id)["Snapshots"][0]["Status"],
        predicate=lambda s: s == "available",
        timeout_s=600,
        interval_s=10,
    )
    snapshot_arn = f"arn:aws:redshift:{region}:{account_id}:snapshot:{cluster_id}/{snapshot_id}"

    # Positive control: the snapshot itself remains describable by its owner.
    snap = redshift.describe_cluster_snapshots(SnapshotIdentifier=snapshot_id)["Snapshots"][0]
    assert snap["SnapshotIdentifier"] == snapshot_id, (
        f"expected owner describe to see {snapshot_id!r}, got {snap!r}"
    )

    snapshot_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowConsumerRestore",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{other_account}:root"},
                "Action": ["redshift:RestoreFromClusterSnapshot", "redshift:DescribeClusterSnapshots"],
                "Resource": snapshot_arn,
            }
        ],
    }
    error = _client_error(lambda: redshift.put_resource_policy(ResourceArn=snapshot_arn, Policy=json.dumps(snapshot_policy)))
    assert error["Code"] == "InvalidParameterValue", (
        f"expected PutResourcePolicy on a snapshot ARN to be refused with InvalidParameterValue, got {error!r}"
    )
    assert error["Message"] == _UNSUPPORTED_SNAPSHOT, (
        f"expected the refusal to name the unsupported resource type, got message: {error['Message']!r}"
    )

    # Independent read (a different operation, GetResourcePolicy) corroborates: the
    # snapshot resource type itself is unsupported, not merely lacking a policy.
    get_snapshot_error = _client_error(lambda: redshift.get_resource_policy(ResourceArn=snapshot_arn))
    assert get_snapshot_error["Code"] == "InvalidParameterValue", (
        f"expected GetResourcePolicy on a snapshot ARN to be refused with InvalidParameterValue too, got {get_snapshot_error!r}"
    )
    assert get_snapshot_error["Message"] == _UNSUPPORTED_SNAPSHOT, (
        f"expected the refusal to name the unsupported resource type, got message: {get_snapshot_error['Message']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    accepting input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected this call to be refused by real AWS, but it SUCCEEDED and returned {result!r}")


def _generate_password() -> str:
    alphabet = string.ascii_letters + string.digits
    body = "".join(secrets.choice(alphabet) for _ in range(20))
    return "Aa1" + body


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _create_available_cluster(ctx: Any, redshift: Any) -> str:
    cluster_id = ctx.unique_name("sim2real-rsrp-").lower().replace("_", "-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType="ra3.xlplus",
        ClusterType="single-node",
        MasterUsername="s2radmin",
        MasterUserPassword=_generate_password(),
        DBName="dev",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))
    _poll_until(
        probe=lambda: redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]["ClusterStatus"],
        predicate=lambda s: s == "available",
        timeout_s=900,
        interval_s=15,
    )
    return cluster_id


def _delete_cluster(redshift: Any, cluster_id: str) -> None:
    """Delete the cluster and wait until it is gone. DeleteCluster answers
    InvalidClusterState while a just-finished snapshot operation still holds the
    cluster, so that is retried; any other failure surfaces."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 900
    while True:
        try:
            redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code != "InvalidClusterState" or time.monotonic() > deadline:
                raise
            time.sleep(15)
    while time.monotonic() < deadline:
        try:
            redshift.describe_clusters(ClusterIdentifier=cluster_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ClusterNotFound":
                return
            raise
        time.sleep(15)
    raise AssertionError(f"cluster {cluster_id} was not deleted within 900s")


def _delete_snapshot(redshift: Any, snapshot_id: str) -> None:
    try:
        redshift.delete_cluster_snapshot(SnapshotIdentifier=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterSnapshotNotFound":
            raise


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
