"""get-cluster-credentials-with-iam-returns-usable-credentials."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-cluster-credentials-with-iam-returns-usable-credentials"
GROUP = "overly-permissive"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetClusterCredentialsWithIAM on a nonexistent cluster is ClusterNotFound; on an available
    cluster it returns a non-empty DbUser and DbPassword expiring after the requested 900 s."""
    redshift = ctx.client("redshift")

    bogus_cluster_id = ctx.unique_name("sim2real-credsiam-ghost-")
    code, message = _error(
        lambda: redshift.get_cluster_credentials_with_iam(ClusterIdentifier=bogus_cluster_id)
    )
    assert code == "ClusterNotFound", f"expected ClusterNotFound for a nonexistent cluster, got {code!r}"
    expected = f"Cluster {bogus_cluster_id} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    cluster_id = _create_available_cluster(ctx)

    before = datetime.now(timezone.utc)
    creds = redshift.get_cluster_credentials_with_iam(
        ClusterIdentifier=cluster_id, DbName="dev", DurationSeconds=900
    )
    after = datetime.now(timezone.utc)

    assert isinstance(creds.get("DbUser"), str) and creds["DbUser"], (
        f"expected a non-empty string DbUser, got {creds.get('DbUser')!r}"
    )
    assert isinstance(creds.get("DbPassword"), str) and creds["DbPassword"], (
        f"expected a non-empty string DbPassword, got {creds.get('DbPassword')!r}"
    )
    expiration = creds["Expiration"]
    # The expiry is bounded from both sides of the call.
    assert before + timedelta(seconds=890) <= expiration <= after + timedelta(seconds=910), (
        f"Expiration {expiration} not within the requested 900s window ({before} .. {after})"
    )


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises, so a
    target that mints credentials for a nonexistent cluster is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_available_cluster(ctx) -> str:
    redshift = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-credsiam-cl-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    # Redshift creates AWSServiceRoleForRedshift on an account's first cluster; until that role
    # propagates, CreateCluster answers InvalidParameterValue "Unable to assume the SLR on the
    # customer account". Retry that one refusal; anything else raises.
    deadline = time.monotonic() + 600
    while True:
        try:
            redshift.create_cluster(
                ClusterIdentifier=cluster_id,
                NodeType="ra3.xlplus",
                MasterUsername="sim2realadmin",
                ManageMasterPassword=True,
                ClusterType="single-node",
                PubliclyAccessible=False,
                Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
                ClusterSubnetGroupName=subnet_group,
            )
            break
        except ClientError as err:
            if "Unable to assume the SLR" not in err.response["Error"].get("Message", "") or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_id))
    _wait_for_cluster_status(ctx, cluster_id, {"available"}, timeout_s=900)
    return cluster_id


def _wait_for_cluster_status(ctx, cluster_id: str, targets: set, timeout_s: float) -> None:
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        if cluster["ClusterStatus"] in targets:
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} never reached {targets} within {timeout_s}s")


def _delete_cluster(ctx, cluster_id: str) -> None:
    """Delete the cluster (retrying while an operation still runs on it) and wait until it is gone."""
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + 900
    while True:
        try:
            redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(15)
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            redshift.describe_clusters(ClusterIdentifier=cluster_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ClusterNotFound":
                return
            raise
        time.sleep(15)
    raise AssertionError(f"Redshift cluster {cluster_id} still exists 900s after DeleteCluster")


def _network_redshift_subnet_group(ctx, client) -> str:
    """A Redshift cluster subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-rsg-")
    client.create_cluster_subnet_group(
        ClusterSubnetGroupName=name,
        Description="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cluster_subnet_group(ClusterSubnetGroupName=name),
            ("InvalidClusterSubnetGroupStateFault", "ClusterSubnetGroupInUse"),
            ("ClusterSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=300.0, interval_s=15.0):
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
