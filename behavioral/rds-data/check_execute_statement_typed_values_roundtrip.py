"""execute-statement-typed-values-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-typed-values-roundtrip"
GROUP = "data-plane"
SERVICES = ["rds-data"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Typed SQL parameters (long/double/string/isNull) round-trip through
    ExecuteStatement to the correctly-typed Field in the SELECT result."""
    db = _provision_cluster(ctx)
    rdsdata = ctx.client("rds-data")
    table = ctx.unique_name("t_types_").replace("-", "_")

    rdsdata.execute_statement(
        resourceArn=db["resourceArn"],
        secretArn=db["secretArn"],
        database=db["database"],
        sql=f"CREATE TABLE {table} (id INT PRIMARY KEY, price DOUBLE, label VARCHAR(32), note VARCHAR(32))",
    )
    ctx.on_cleanup(
        lambda: rdsdata.execute_statement(
            resourceArn=db["resourceArn"],
            secretArn=db["secretArn"],
            database=db["database"],
            sql=f"DROP TABLE IF EXISTS {table}",
        )
    )
    rdsdata.execute_statement(
        resourceArn=db["resourceArn"],
        secretArn=db["secretArn"],
        database=db["database"],
        sql=f"INSERT INTO {table} (id, price, label, note) VALUES (:id, :price, :label, :note)",
        parameters=[
            {"name": "id", "value": {"longValue": 1}},
            {"name": "price", "value": {"doubleValue": 3.5}},
            {"name": "label", "value": {"stringValue": "widget"}},
            {"name": "note", "value": {"isNull": True}},
        ],
    )

    resp = rdsdata.execute_statement(
        resourceArn=db["resourceArn"],
        secretArn=db["secretArn"],
        database=db["database"],
        sql=f"SELECT id, price, label, note FROM {table} WHERE id = 1",
    )
    row = resp["records"][0]
    assert row[0]["longValue"] == 1, (
        f"a longValue parameter (id=1) must round-trip through INT to longValue; got {row[0]!r}"
    )
    assert row[1]["doubleValue"] == 3.5, (
        f"a doubleValue parameter (price=3.5) must round-trip through DOUBLE to doubleValue; "
        f"got {row[1]!r}"
    )
    assert row[2]["stringValue"] == "widget", (
        f"a stringValue parameter (label='widget') must round-trip through VARCHAR to "
        f"stringValue; got {row[2]!r}"
    )
    assert row[3] == {"isNull": True}, (
        f"an isNull=True parameter (note) must round-trip to exactly {{'isNull': True}}, not a "
        f"stringValue of '' or 'NULL' and not carrying any other arm; got {row[3]!r}"
    )


# rds-data's data plane IS the AWS API (ExecuteStatement/BatchExecuteStatement/...) — there's no
# separate native-protocol round-trip to gate behind an opt-in flag, so nothing connects to the
# cluster and its security group admits nothing. Each check creates its own Aurora Serverless v2
# cluster and writer in the run's shared network (~10 min) and tears them down; the admin
# password is managed by RDS in Secrets Manager, so the check never handles one.


def _wait_until(probe, predicate, timeout_s=900, interval_s=10):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met, last observed: {last}")


def _wait_data_api_ready(ctx, resource_arn, secret_arn, timeout_s=300):
    rdsdata = ctx.client("rds-data")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            rdsdata.execute_statement(resourceArn=resource_arn, secretArn=secret_arn, sql="SELECT 1")
            return
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code in (
                "DatabaseResumingException",
                "HttpEndpointNotEnabledException",
                "DatabaseNotFoundException",
                "ServiceUnavailableError",
                "DatabaseUnavailableException",
            ):
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"Data API never became ready (last error: {last_code})")


def _create_clusters(ctx, http_endpoint_flags):
    """Create one Aurora Serverless v2 cluster and writer per flag (EnableHttpEndpoint) in the
    run's shared network, all in one subnet group and one security group, and register one
    teardown for all of them. Returns their handles without waiting (see _await_cluster), so
    several clusters provision concurrently. The security group admits nothing (the Data API is
    an AWS API, not a connection to the cluster); it exists so the teardown can wait for the
    writers' network interfaces to detach."""
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")
    network = ctx.network()
    base = ctx.unique_name("sim2real-behav-rdsdata-")
    subnet_group_name = f"{base}-subnets"
    tags = [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    ]
    sg_id = ec2.create_security_group(
        GroupName=f"{base}-sg",
        Description="sim2real rds-data check",
        VpcId=network.vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tags}],
    )["GroupId"]
    dbs = []
    ctx.on_cleanup(lambda: _delete_clusters(rds, ec2, dbs, subnet_group_name, sg_id))
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real rds-data check",
        SubnetIds=network.subnet_ids,
        Tags=tags,
    )
    for n, enable_http_endpoint in enumerate(http_endpoint_flags):
        cluster_id = f"{base}-c{n}"
        db = {"clusterId": cluster_id, "instanceId": f"{cluster_id}-i", "database": "simparitydb"}
        dbs.append(db)
        db["resourceArn"] = rds.create_db_cluster(
            DBClusterIdentifier=cluster_id,
            Engine="aurora-mysql",
            DatabaseName="simparitydb",
            MasterUsername="simparity",
            ManageMasterUserPassword=True,
            EnableHttpEndpoint=enable_http_endpoint,
            ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 2.0},
            StorageEncrypted=True,
            DeletionProtection=False,
            DBSubnetGroupName=subnet_group_name,
            VpcSecurityGroupIds=[sg_id],
            Tags=tags,
        )["DBCluster"]["DBClusterArn"]
        rds.create_db_instance(
            DBInstanceIdentifier=db["instanceId"],
            DBClusterIdentifier=cluster_id,
            Engine="aurora-mysql",
            DBInstanceClass="db.serverless",
            Tags=tags,
        )
    return dbs


def _await_cluster(ctx, db):
    """Wait until a cluster from _create_clusters and its writer are available (and, with the
    HTTP endpoint on, until the Data API answers), then return its handle with the secret ARN."""
    rds = ctx.client("rds")
    _wait_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=db["instanceId"])["DBInstances"][0]["DBInstanceStatus"],
        lambda status: status == "available",
        timeout_s=1200,
    )
    cluster = _wait_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=db["clusterId"])["DBClusters"][0],
        lambda c: c["Status"] == "available" and "MasterUserSecret" in c,
        timeout_s=600,
    )
    db["secretArn"] = cluster["MasterUserSecret"]["SecretArn"]
    if cluster.get("HttpEndpointEnabled"):
        _wait_data_api_ready(ctx, db["resourceArn"], db["secretArn"])
    return db


def _provision_cluster(ctx, enable_http_endpoint=True):
    """Create this check's own Aurora Serverless v2 cluster and wait until it is usable."""
    return _await_cluster(ctx, _create_clusters(ctx, [enable_http_endpoint])[0])


def _delete_clusters(rds, ec2, dbs, subnet_group_name, sg_id):
    """Delete the writers, then the clusters (no final snapshot; each managed admin-user secret
    goes with its cluster), wait for their network interfaces to detach, then delete the subnet
    group and the security group, waiting for each delete. Every step runs even if an earlier one
    fails; then the teardown raises naming each step that failed. The waits sum to at most
    1740 s, inside the suite's 1800 s teardown budget.
    """
    def _gone(resources, gone_code, busy_codes, timeout_s):
        deadline = time.monotonic() + timeout_s
        pending = {i: False for i in range(len(resources))}
        while True:
            for i, accepted in list(pending.items()):
                delete, describe = resources[i]
                try:
                    if not accepted:
                        delete()
                        pending[i] = True
                    describe()
                except ClientError as exc:
                    code = exc.response["Error"]["Code"]
                    if code == gone_code:
                        del pending[i]
                        continue
                    if code not in busy_codes:
                        raise
            if not pending:
                return
            if time.monotonic() >= deadline:
                raise TimeoutError(f"{len(pending)} still present after {timeout_s}s")
            time.sleep(15)

    def _enis_detached(timeout_s):
        deadline = time.monotonic() + timeout_s
        while True:
            enis = ec2.describe_network_interfaces(
                Filters=[{"Name": "group-id", "Values": [sg_id]}]
            )["NetworkInterfaces"]
            if not enis:
                return
            if time.monotonic() >= deadline:
                ids = [e["NetworkInterfaceId"] for e in enis]
                raise TimeoutError(f"{ids} still attached after {timeout_s}s")
            time.sleep(15)

    def _instance(db):
        return (
            lambda: rds.delete_db_instance(DBInstanceIdentifier=db["instanceId"], SkipFinalSnapshot=True),
            lambda: rds.describe_db_instances(DBInstanceIdentifier=db["instanceId"]),
        )

    def _cluster(db):
        return (
            lambda: rds.delete_db_cluster(DBClusterIdentifier=db["clusterId"], SkipFinalSnapshot=True),
            lambda: rds.describe_db_clusters(DBClusterIdentifier=db["clusterId"]),
        )

    # Wire codes as the rds model's awsQueryError traits give them: DBInstanceNotFound and
    # InvalidDBInstanceState drop "Fault"; DBClusterNotFoundFault, InvalidDBClusterStateFault,
    # DBSubnetGroupNotFoundFault and InvalidDBSubnetGroupStateFault keep it.
    steps = [
        ("writers", lambda: _gone(
            [_instance(db) for db in dbs], "DBInstanceNotFound", {"InvalidDBInstanceState"}, 900,
        )),
        ("clusters", lambda: _gone(
            [_cluster(db) for db in dbs], "DBClusterNotFoundFault", {"InvalidDBClusterStateFault"}, 450,
        )),
        (f"network interfaces in {sg_id}", lambda: _enis_detached(180)),
        (f"subnet group {subnet_group_name}", lambda: _gone(
            [(
                lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name),
                lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=subnet_group_name),
            )],
            "DBSubnetGroupNotFoundFault", {"InvalidDBSubnetGroupStateFault"}, 90,
        )),
        (f"security group {sg_id}", lambda: _gone(
            [(
                lambda: ec2.delete_security_group(GroupId=sg_id),
                lambda: ec2.describe_security_groups(GroupIds=[sg_id]),
            )],
            "InvalidGroup.NotFound", {"DependencyViolation"}, 120,
        )),
    ]
    failures = []
    for what, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - every step runs; each failure is raised below
            failures.append(f"{what} of {[db['clusterId'] for db in dbs]}: {exc!r}")
    if failures:
        raise RuntimeError(f"rds-data teardown failed: {'; '.join(failures)}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

