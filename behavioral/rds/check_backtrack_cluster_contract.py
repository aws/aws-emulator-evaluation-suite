"""backtrack-cluster-contract."""
from __future__ import annotations

import secrets
import string
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "backtrack-cluster-contract"
GROUP = 'errors'
SERVICES = ['rds']

ERR_DB_CLUSTER_NOT_FOUND = "DBClusterNotFoundFault"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BacktrackDBCluster on a nonexistent cluster fails with DBClusterNotFoundFault ("Could not
    find specified DB Cluster"), while an existing backtrack-ineligible cluster gets a different
    fault."""
    rds = ctx.client("rds")

    real_cluster_id = ctx.unique_name("sim2real-behav-clu-real-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=real_cluster_id,
        Engine="aurora-mysql",
        MasterUsername="s2radmin",
        MasterUserPassword=_rand_password(),
        DeletionProtection=False,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
        # BacktrackWindow intentionally omitted (defaults to 0 -- backtrack disabled), so the
        # cluster below is real but permanently ineligible for backtrack -- exactly what makes it
        # a control rather than a redundant success path.
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=real_cluster_id, SkipFinalSnapshot=True)
    )

    backtrack_to = datetime.now(timezone.utc) - timedelta(minutes=5)
    real_code, _real_message = _error_code(
        lambda: rds.backtrack_db_cluster(
            DBClusterIdentifier=real_cluster_id, BacktrackTo=backtrack_to, Force=True
        )
    )
    assert real_code != ERR_DB_CLUSTER_NOT_FOUND, (
        f"a real cluster must not be rejected as not-found, got {real_code!r}"
    )

    bogus_id = ctx.unique_name("sim2real-behav-clu-missing-")
    missing_code, missing_message = _error_code(
        lambda: rds.backtrack_db_cluster(DBClusterIdentifier=bogus_id, BacktrackTo=backtrack_to)
    )
    assert missing_code == ERR_DB_CLUSTER_NOT_FOUND, f"unexpected error code: {missing_code!r}"
    assert missing_message == "Could not find specified DB Cluster", missing_message

    _wait_cluster_status(ctx, real_cluster_id, "available", timeout_s=900)


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected BacktrackDBCluster to raise, it returned success")


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _wait_cluster_status(ctx, cluster_id, target_status, timeout_s=900, poll_s=20) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"cluster {cluster_id} never reached {target_status!r}, last status {last and last['Status']!r}"
    )


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
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
