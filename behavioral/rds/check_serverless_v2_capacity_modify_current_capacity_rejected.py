"""serverless-v2-capacity-modify-current-capacity-rejected."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "serverless-v2-capacity-modify-current-capacity-rejected"
GROUP = "server-side"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyCurrentDBClusterCapacity is rejected with InvalidParameterValue on an Aurora Serverless
    v2 cluster (it applies to v1 only) and leaves the scaling range unchanged, while
    ModifyDBCluster can change that range."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-sv2cap-")
    password = _rand_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        DeletionProtection=False,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 2.0},
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    cluster = _wait_cluster_status(ctx, cluster_id, "available", timeout_s=900)
    assert cluster["ServerlessV2ScalingConfiguration"]["MaxCapacity"] == 2.0

    # Ask for a capacity far above the configured v2 max through the v1-only API.
    error = _client_error(
        lambda: rds.modify_current_db_cluster_capacity(
            DBClusterIdentifier=cluster_id, Capacity=256
        )
    )
    # AWS rejects it as a parameter-validation error, not a cluster-state error.
    assert error["Code"] == "InvalidParameterValue", f"unexpected error {error!r}"
    assert error["Message"] == (
        "Only Aurora Serverless clusters can have their capacity modified."
    ), f"unexpected message {error['Message']!r}"

    # Effect absent: the configured scaling range is exactly as it was before the rejected call.
    unchanged = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert unchanged["ServerlessV2ScalingConfiguration"]["MaxCapacity"] == 2.0, (
        "ServerlessV2ScalingConfiguration.MaxCapacity changed after a rejected "
        "ModifyCurrentDBClusterCapacity call"
    )
    assert unchanged["ServerlessV2ScalingConfiguration"]["MinCapacity"] == 0.5

    # Positive control: ModifyDBCluster, the API for this cluster mode, changes the range.
    rds.modify_db_cluster(
        DBClusterIdentifier=cluster_id,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 4.0},
        ApplyImmediately=True,
    )
    _wait_max_capacity(ctx, cluster_id, 4.0, timeout_s=180)


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _client_error(fn):
    """Call fn(); return its botocore Error dict. A success raises: AWS refuses this call."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"AWS refuses this call, but it succeeded and returned {result!r}")


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


def _wait_max_capacity(ctx, cluster_id, target_value, timeout_s=180, poll_s=10) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0][
            "ServerlessV2ScalingConfiguration"
        ]["MaxCapacity"]
        if last == target_value:
            return
        time.sleep(poll_s)
    raise AssertionError(
        f"cluster {cluster_id} MaxCapacity never reached {target_value}, last observed {last!r}"
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
