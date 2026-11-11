"""e2e-resource-policy-cross-account-snapshot-share-flow."""
from __future__ import annotations

import time

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-resource-policy-cross-account-snapshot-share-flow"
GROUP = "state-machine"
SERVICES = ["redshift"]


_UNSUPPORTED_SNAPSHOT = (
    "Resource type snapshot isn't supported for the resource policy. Choose another resource type."
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy refuses a snapshot ARN and creates no policy; cross-account sharing goes through
    AuthorizeSnapshotAccess, whose grant and revoke are each confirmed by an independent read.
    """
    redshift = ctx.client("redshift")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    region = ctx.region

    cluster_id = ctx.unique_name("sim2real-snapshare-cl-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(redshift),
        ClusterType="single-node",
        MasterUsername="snapshareadmin",
        MasterUserPassword=_generate_password(),
        DBName="dev",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))
    _wait(ctx, redshift, "cluster_available", f"cluster {cluster_id} never became available",
          ClusterIdentifier=cluster_id)

    snapshot_id = ctx.unique_name("sim2real-snapshare-snap-")
    redshift.create_cluster_snapshot(
        SnapshotIdentifier=snapshot_id,
        ClusterIdentifier=cluster_id,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_snapshot(redshift, snapshot_id, cluster_id))
    _wait(ctx, redshift, "snapshot_available", f"snapshot {snapshot_id} never became available",
          cap_s=1200.0, SnapshotIdentifier=snapshot_id)

    snapshot_arn = f"arn:aws:redshift:{region}:{account}:snapshot:{cluster_id}/{snapshot_id}"
    dummy_account = "111122223333"

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccountDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{dummy_account}:root"},
                "Action": "redshift:DescribeClusterSnapshots",
                "Resource": snapshot_arn,
            }
        ],
    }
    # PutResourcePolicy is documented for redshift-serverless namespace and datashare
    # ARNs; a manual snapshot's "snapshot" resource type is deterministically refused.
    put_code, put_message = _error_code_and_message(
        lambda: redshift.put_resource_policy(ResourceArn=snapshot_arn, Policy=json.dumps(policy))
    )
    assert put_code == "InvalidParameterValue", (
        f"expected PutResourcePolicy on a snapshot ARN to be rejected with "
        f"InvalidParameterValue, got {put_code!r} ({put_message!r})"
    )
    assert put_message == _UNSUPPORTED_SNAPSHOT, (
        f"expected the rejection to name the unsupported resource type, got {put_message!r}"
    )

    # Effect-absent: the refused Put must not have materialised a policy.
    get_code, get_message = _error_code_and_message(
        lambda: redshift.get_resource_policy(ResourceArn=snapshot_arn)
    )
    assert get_code == "InvalidParameterValue", (
        f"expected GetResourcePolicy on a snapshot ARN to be refused the same way "
        f"PutResourcePolicy was, got {get_code!r}"
    )
    assert get_message == _UNSUPPORTED_SNAPSHOT, (
        f"expected the GetResourcePolicy refusal message {_UNSUPPORTED_SNAPSHOT!r}, got {get_message!r}"
    )

    redshift.authorize_snapshot_access(
        SnapshotIdentifier=snapshot_id,
        SnapshotClusterIdentifier=cluster_id,
        AccountWithRestoreAccess=dummy_account,
    )
    ctx.on_cleanup(
        lambda: _revoke_access(redshift, snapshot_id, cluster_id, dummy_account)
    )

    granted = _restore_accounts(redshift, snapshot_id)
    assert dummy_account in granted, (
        f"AuthorizeSnapshotAccess did not record {dummy_account} as having restore "
        f"access, got {granted!r}"
    )

    redshift.revoke_snapshot_access(
        SnapshotIdentifier=snapshot_id,
        SnapshotClusterIdentifier=cluster_id,
        AccountWithRestoreAccess=dummy_account,
    )

    revoked = _restore_accounts(redshift, snapshot_id)
    assert dummy_account not in revoked, (
        f"RevokeSnapshotAccess did not remove {dummy_account}'s restore access, got {revoked!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait(ctx, redshift, waiter_name, message, delay_s=2, cap_s=2400.0, **kwargs):
    """Run a waiter polling every delay_s seconds, bounded by the run's remaining budget."""
    from botocore.exceptions import WaiterError

    attempts = max(1, int(_budget_s(ctx, cap_s) // delay_s))
    try:
        redshift.get_waiter(waiter_name).wait(
            **kwargs, WaiterConfig={"Delay": delay_s, "MaxAttempts": attempts}
        )
    except WaiterError as exc:
        if "Max attempts exceeded" in str(exc) and _budget_spent(ctx):
            raise TimeoutError(
                f"{waiter_name} for {', '.join(str(v) for v in kwargs.values())}: the run budget ended first; not graded"
            ) from exc
        raise AssertionError(f"{message}: {exc}") from exc


def _generate_password() -> str:
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(20))


# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
_NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")


def _node_type(redshift) -> str:
    """Node-type availability varies by account, so the orderable set must be
    read from the account rather than assumed."""
    available: list[str] = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = redshift.describe_orderable_cluster_options(**kwargs)
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != "single-node":
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    for preferred in _NODE_TYPE_PREFERENCE:
        if preferred in available:
            return preferred
    assert available, "no orderable single-node cluster options in this region"
    return sorted(available)[0]


def _error_code_and_message(fn):
    """Call fn(); return its (botocore error code, message). An unexpected SUCCESS
    raises, so accepting a call AWS refuses is never reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


def _restore_accounts(redshift, snapshot_id: str) -> list[str]:
    snap = redshift.describe_cluster_snapshots(SnapshotIdentifier=snapshot_id)["Snapshots"][0]
    # AWS omits the key entirely once the last grant is revoked, rather than
    # returning an empty list -- absence and "no accounts" are the same state.
    return [a["AccountId"] for a in snap.get("AccountsWithRestoreAccess", [])]


def _delete_snapshot(redshift, snapshot_id: str, cluster_id: str) -> None:
    try:
        redshift.delete_cluster_snapshot(
            SnapshotIdentifier=snapshot_id, SnapshotClusterIdentifier=cluster_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterSnapshotNotFound":
            raise
        return
    # Redshift has no snapshot_deleted waiter: poll until the snapshot is gone.
    deadline = time.monotonic() + 600.0
    while True:
        try:
            redshift.describe_cluster_snapshots(SnapshotIdentifier=snapshot_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ClusterSnapshotNotFound":
                return
            raise
        if time.monotonic() > deadline:
            raise AssertionError(f"snapshot {snapshot_id} still listed 600 s after DeleteClusterSnapshot")
        time.sleep(2)


def _delete_cluster(redshift, cluster_id: str) -> None:
    """Delete the cluster, waiting out the window in which a just-finished snapshot
    operation still holds it (DeleteCluster answers InvalidClusterState until then)."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 600
    while True:
        try:
            redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code != "InvalidClusterState" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    redshift.get_waiter("cluster_deleted").wait(
        ClusterIdentifier=cluster_id, WaiterConfig={"Delay": 2, "MaxAttempts": 870}
    )


def _revoke_access(redshift, snapshot_id: str, cluster_id: str, account: str) -> None:
    try:
        redshift.revoke_snapshot_access(
            SnapshotIdentifier=snapshot_id,
            SnapshotClusterIdentifier=cluster_id,
            AccountWithRestoreAccess=account,
        )
    except ClientError as exc:
        # AWS answers AccessToSnapshotDenied for a grant that is already revoked.
        if exc.response["Error"]["Code"] not in (
            "AuthorizationNotFound",
            "AccessToSnapshotDenied",
            "ClusterSnapshotNotFound",
        ):
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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=2.0):
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
