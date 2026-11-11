"""modify-cluster-capacity-invalid-value-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-cluster-capacity-invalid-value-rejected"
GROUP = "negative-classes"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """No aurora-mysql engine version advertises serverless mode, and CreateDBCluster with
    EngineMode=serverless is rejected with InvalidParameterValue and its exact message and leaves no
    cluster, while creating a DB parameter group in the same run succeeds."""
    from botocore.exceptions import ClientError

    rds = ctx.client("rds")

    # Positive control: RDS mutating access is healthy in this account, so the serverless
    # refusal below cannot be confused with "everything is denied here".
    pg_name = ctx.unique_name("sim2real-rdscap-pg-")
    versions = rds.describe_db_engine_versions(Engine="aurora-mysql")["DBEngineVersions"]
    assert versions, "DescribeDBEngineVersions(Engine=aurora-mysql) returned no versions at all"
    probe_version = sorted(versions, key=lambda v: v["EngineVersion"])[-1]
    rds.create_db_parameter_group(
        DBParameterGroupName=pg_name,
        DBParameterGroupFamily=probe_version["DBParameterGroupFamily"],
        Description="sim2real serverless-v1-withdrawal positive control",
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=pg_name))
    described = rds.describe_db_parameter_groups(DBParameterGroupName=pg_name)["DBParameterGroups"]
    assert described and described[0]["DBParameterGroupName"] == pg_name, (
        f"positive control failed: {pg_name!r} not visible via an independent "
        f"DescribeDBParameterGroups read right after CreateDBParameterGroup -- RDS mutating "
        f"access looks unhealthy in this account, which would make the serverless refusal "
        f"below meaningless"
    )

    # Withdrawal, shape 1: the catalog itself no longer offers the mode.
    serverless_candidates = [
        v["EngineVersion"] for v in versions if "serverless" in v.get("SupportedEngineModes", [])
    ]
    assert not serverless_candidates, (
        f"expected NO aurora-mysql engine version to advertise EngineMode=serverless support "
        f"(Aurora Serverless v1 was withdrawn for new clusters 2025-03-31), but "
        f"DescribeDBEngineVersions returned {serverless_candidates!r} -- this account may still "
        f"have Serverless v1 access; re-scope this check back to the original "
        f"ModifyCurrentDBClusterCapacity contract instead of the withdrawal"
    )

    # Withdrawal, shape 2: the refusal is also observable on the actual mutating call, not
    # just absent from the catalog.
    cluster_id = ctx.unique_name("sim2real-rdscap-cluster-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    err = _client_error(
        lambda: rds.create_db_cluster(
            DBClusterIdentifier=cluster_id,
            Engine="aurora-mysql",
            EngineVersion=probe_version["EngineVersion"],
            EngineMode="serverless",
            MasterUsername="s2radmin",
            MasterUserPassword=_admin_password(),
            ScalingConfiguration={"MinCapacity": 2, "MaxCapacity": 16, "AutoPause": False},
            DBSubnetGroupName=subnet_group,
        )
    )
    assert err.get("Code") == "InvalidParameterValue", (
        f"expected InvalidParameterValue rejecting EngineMode=serverless "
        f"(Aurora Serverless v1 is withdrawn for new clusters), got {err.get('Code')!r}"
    )
    expected = "The engine mode serverless you requested is currently unavailable."
    assert err.get("Message") == expected, (
        f"expected message {expected!r}, got {err.get('Message')!r}"
    )

    # Effect absent: no cluster was created as a side effect of the rejected call.
    try:
        rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        raise AssertionError(
            f"cluster {cluster_id!r} is visible via an independent DescribeDBClusters read "
            f"despite CreateDBCluster having been rejected"
        )
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "DBClusterNotFoundFault", (
            f"expected DBClusterNotFoundFault confirming {cluster_id!r} was never created, "
            f"got {exc.response['Error']['Code']!r}"
        )
        expected_nf = f"DBCluster {cluster_id} not found."
        assert exc.response["Error"].get("Message") == expected_nf, (
            f"expected message {expected_nf!r}, got {exc.response['Error'].get('Message')!r}"
        )


def _admin_password() -> str:
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return "Sim2Real1" + "".join(secrets.choice(alphabet) for _ in range(12))


def _client_error(fn) -> dict:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
