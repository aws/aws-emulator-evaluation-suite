"""modify-cluster-capacity-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

import secrets
import string

import botocore.exceptions

from behavioral_harness import tags

CHECK = "modify-cluster-capacity-out-of-range-rejected"
GROUP = "negative-classes"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """No aurora-mysql engine version advertises serverless mode, and CreateDBCluster with
    EngineMode='serverless' on the latest version is rejected with InvalidParameterValue and its exact
    message and leaves no cluster behind."""
    rds = ctx.client("rds")

    # Positive control: RDS is reachable and these credentials are not simply denied everything.
    versions = rds.describe_db_engine_versions(Engine="aurora-mysql")["DBEngineVersions"]
    assert versions, (
        "DescribeDBEngineVersions(Engine=aurora-mysql) returned zero results -- RDS itself is "
        "unreachable in this account, not a serverless-v1-specific finding"
    )

    serverless_versions = [
        v["EngineVersion"]
        for v in versions
        if "serverless" in v.get("SupportedEngineModes", []) and v.get("Status") == "available"
    ]
    assert not serverless_versions, (
        "Aurora Serverless v1 appears to be available again in this account/region (engine "
        f"versions {serverless_versions!r} advertise EngineMode='serverless' support) -- this "
        "check needs rewriting back to a real capacity-rejection test against a live v1 cluster "
        "instead of asserting the withdrawal"
    )

    latest_version = sorted(v["EngineVersion"] for v in versions)[-1]
    cluster_id = ctx.unique_name("sim2real-svl1-")
    code, message = _create_serverless_v1(ctx, rds, cluster_id, latest_version)
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue rejecting CreateDBCluster(EngineMode='serverless') on "
        f"engine version {latest_version!r}, got {code!r} ({message!r})"
    )
    expected = "The engine mode serverless you requested is currently unavailable."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected cluster must not exist.
    clusters = rds.describe_db_clusters()["DBClusters"]
    ids = {c["DBClusterIdentifier"] for c in clusters}
    assert cluster_id not in ids, (
        f"cluster {cluster_id!r} unexpectedly exists after a rejected "
        "CreateDBCluster(EngineMode='serverless') call"
    )


def _create_serverless_v1(ctx, rds, cluster_id: str, engine_version: str) -> tuple[str, str | None]:
    """Attempt CreateDBCluster(EngineMode='serverless'); registers cleanup up front in case the
    withdrawal ever lifts and the call unexpectedly succeeds. Returns (error_code, message); an
    unexpected SUCCESS raises, because a target accepting a call real AWS refuses must not read
    as a code mismatch."""
    ctx.on_cleanup(lambda: _safe_delete_cluster(rds, cluster_id))
    subnet_group = _network_db_subnet_group(ctx, rds)
    try:
        rds.create_db_cluster(
            DBClusterIdentifier=cluster_id,
            Engine="aurora-mysql",
            EngineVersion=engine_version,
            EngineMode="serverless",
            MasterUsername="s2radmin",
            MasterUserPassword=_rand_password(),
            ScalingConfiguration={"MinCapacity": 1, "MaxCapacity": 2, "AutoPause": False},
            DeletionProtection=False,
            Tags=[{"Key": "sim2real-probe", "Value": CHECK}],
            DBSubnetGroupName=subnet_group,
        )
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected CreateDBCluster(EngineMode='serverless') to be rejected, but it SUCCEEDED "
        f"and created {cluster_id!r}"
    )


def _safe_delete_cluster(rds, cluster_id: str) -> None:
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except botocore.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] not in ("DBClusterNotFoundFault", "InvalidDBClusterStateFault"):
            raise


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


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
