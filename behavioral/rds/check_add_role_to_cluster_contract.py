"""add-role-to-cluster-contract."""
from __future__ import annotations

import json
import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-role-to-cluster-contract"
GROUP = 'errors'
SERVICES = ['rds']

ERR_DB_CLUSTER_NOT_FOUND = "DBClusterNotFoundFault"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddRoleToDBCluster on a nonexistent cluster is rejected with DBClusterNotFoundFault.
    The same call against a real cluster with an rds.amazonaws.com-trusted role is accepted,
    so the rejection is specific to the missing cluster."""
    rds = ctx.client("rds")
    iam = ctx.client("iam")

    role_arn = _create_trusted_role(ctx, iam)
    cluster_id = ctx.unique_name("sim2real-behav-clu-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="s2radmin",
        MasterUserPassword=_rand_password(),
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 1},
        DeletionProtection=False,
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(rds, cluster_id))
    _wait_cluster_status(rds, cluster_id, "available", timeout_s=_capped(ctx, 900))

    # Positive control (same file): a real cluster + a properly-trusted role is accepted.
    rds.add_role_to_db_cluster(DBClusterIdentifier=cluster_id, RoleArn=role_arn)
    associated = _wait_role_present(rds, cluster_id, role_arn, timeout_s=_capped(ctx, 120))
    assert associated["RoleArn"] == role_arn, (
        f"positive control: trusted role not associated with real cluster: {associated!r}"
    )

    # Negative: the identical call against a cluster id that has never existed. Always-invalid
    # by construction -- a fresh unique id can never become valid, so there is no restore leg.
    bogus_id = ctx.unique_name("sim2real-behav-clu-missing-")
    code = message = None
    try:
        rds.add_role_to_db_cluster(DBClusterIdentifier=bogus_id, RoleArn=role_arn)
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    assert code == ERR_DB_CLUSTER_NOT_FOUND, f"unexpected error code: {code!r}"
    assert message == f"DBCluster not found: {bogus_id}", message


# ===== helpers =====

def _create_trusted_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    return role_arn


def _delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _delete_cluster(rds, cluster_id: str) -> None:
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBClusterNotFoundFault":
            raise


def _capped(ctx, cap_s):
    """cap_s, bounded by the runner's remaining time when it has one."""
    left = ctx.time_left()
    return cap_s if left is None else min(cap_s, left)


def _wait_cluster_status(rds, cluster_id: str, status: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if cluster["Status"] == status:
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} never reached status={status!r} in {timeout_s}s")


def _wait_role_present(rds, cluster_id: str, role_arn: str, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        for role in cluster.get("AssociatedRoles", []):
            if role["RoleArn"] == role_arn:
                return role
        last = cluster.get("AssociatedRoles", [])
        time.sleep(2)
    raise AssertionError(
        f"role {role_arn} never appeared on cluster {cluster_id} within {timeout_s}s (last={last!r})"
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
