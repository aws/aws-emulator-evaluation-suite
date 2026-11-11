"""execute-statement-with-another-clusters-transaction-id-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-with-another-clusters-transaction-id-rejected"
GROUP = "transactions"
SERVICES = ["rds", "rds-data", "secretsmanager"]

# One Aurora Serverless v2 cluster per handle (0.5 ACU floor) with the Data API on. Nothing
# connects to the engine port, so the security group admits nothing; it exists so the teardown
# can wait for the writers' network interfaces to detach. The admin-user password is managed by RDS
# in Secrets Manager.

_DB = "simparitydb"
_USER = "simparity"
_PORTS = {"aurora-postgresql": 5432, "aurora-mysql": 3306}
_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": "rds-data-native-cross-surface"},
]


def _wait_until(probe, predicate, *, timeout_s, interval_s=10.0):
    """probe() until predicate(value) holds; raise naming the last value when the deadline passes."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition never met within {timeout_s}s; last observed {last!r}")
        time.sleep(interval_s)


def _provision(ctx, engine, count=1):
    """Create `count` Data API clusters of `engine` with a writer each, wait until the Data API
    answers, and return their handles. One teardown deletes all of them."""
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")
    network = ctx.network()
    base = ctx.unique_name("sim2real-behav-xsurf-")
    subnet_group = f"{base}-subnets"
    sg_id = ec2.create_security_group(
        GroupName=f"{base}-sg",
        Description="sim2real data api and native sql",
        VpcId=network.vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _TAGS}],
    )["GroupId"]
    dbs = []
    ctx.on_cleanup(lambda: _delete_clusters(rds, ec2, dbs, subnet_group, sg_id))
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group,
        DBSubnetGroupDescription="sim2real data api and native sql",
        SubnetIds=network.subnet_ids,
        Tags=_TAGS,
    )
    for n in range(count):
        cluster_id = f"{base}-c{n}"
        db = {"clusterId": cluster_id, "instanceId": f"{cluster_id}-i", "engine": engine}
        dbs.append(db)
        db["resourceArn"] = rds.create_db_cluster(
            DBClusterIdentifier=cluster_id,
            Engine=engine,
            DatabaseName=_DB,
            MasterUsername=_USER,
            ManageMasterUserPassword=True,
            EnableHttpEndpoint=True,
            ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 4.0},
            BackupRetentionPeriod=1,
            DeletionProtection=False,
            DBSubnetGroupName=subnet_group,
            VpcSecurityGroupIds=[sg_id],
            Tags=_TAGS,
        )["DBCluster"]["DBClusterArn"]
        rds.create_db_instance(
            DBInstanceIdentifier=db["instanceId"],
            DBClusterIdentifier=cluster_id,
            Engine=engine,
            DBInstanceClass="db.serverless",
            Tags=_TAGS,
        )
    return [_await_cluster(ctx, db) for db in dbs]


def _await_cluster(ctx, db):
    """Wait for the writer and the cluster, then until the Data API answers; return the handle."""
    rds = ctx.client("rds")
    _wait_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=db["instanceId"])["DBInstances"][0][
            "DBInstanceStatus"
        ],
        lambda status: status == "available",
        timeout_s=1500,
        interval_s=15,
    )
    cluster = _wait_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=db["clusterId"])["DBClusters"][0],
        lambda c: c["Status"] == "available"
        and (c.get("MasterUserSecret") or {}).get("SecretStatus") == "active",
        timeout_s=900,
        interval_s=15,
    )
    assert cluster["HttpEndpointEnabled"] is True, (
        f"a cluster created with EnableHttpEndpoint must report HttpEndpointEnabled=True; got "
        f"{cluster['HttpEndpointEnabled']!r}"
    )
    db["secretArn"] = cluster["MasterUserSecret"]["SecretArn"]
    _wait_data_api_ready(ctx, db)
    return db


def _wait_data_api_ready(ctx, db, timeout_s=600):
    """A trivial ExecuteStatement until the Data API accepts one; only start-up codes retry."""
    data = ctx.client("rds-data")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            data.execute_statement(
                resourceArn=db["resourceArn"], secretArn=db["secretArn"], database=_DB,
                sql="SELECT 1",
            )
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in (
                "DatabaseResumingException",
                "HttpEndpointNotEnabledException",
                "DatabaseNotFoundException",
                "ServiceUnavailableError",
                "DatabaseUnavailableException",
            ) or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _sql(ctx, db, sql, *, txn=None, params=None, **extra):
    """One Data API ExecuteStatement on `db`, inside `txn` when given."""
    req = {
        "resourceArn": db["resourceArn"], "secretArn": db["secretArn"], "database": _DB,
        "sql": sql, **extra,
    }
    if txn is not None:
        req["transactionId"] = txn
    if params:
        req["parameters"] = params
    return ctx.client("rds-data").execute_statement(**req)


def _begin(ctx, db):
    return ctx.client("rds-data").begin_transaction(
        resourceArn=db["resourceArn"], secretArn=db["secretArn"], database=_DB
    )["transactionId"]


def _commit(ctx, db, txn):
    return ctx.client("rds-data").commit_transaction(
        resourceArn=db["resourceArn"], secretArn=db["secretArn"], transactionId=txn
    )["transactionStatus"]


def _rollback(ctx, db, txn):
    return ctx.client("rds-data").rollback_transaction(
        resourceArn=db["resourceArn"], secretArn=db["secretArn"], transactionId=txn
    )["transactionStatus"]


def _delete_clusters(rds, ec2, dbs, subnet_group_name, sg_id):
    """Delete the writers, then the clusters (no final snapshot; each RDS-managed admin-user secret
    goes with its cluster), wait for their network interfaces to detach, then delete the subnet
    group and the security group. Every step runs even if an earlier one fails; then the teardown
    raises naming each step that failed."""

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
                raise TimeoutError(f"{len(enis)} network interface(s) still attached after {timeout_s}s")
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

    steps = [
        ("writers", lambda: _gone(
            [_instance(db) for db in dbs], "DBInstanceNotFound", {"InvalidDBInstanceState"}, 900,
        )),
        ("clusters", lambda: _gone(
            [_cluster(db) for db in dbs], "DBClusterNotFoundFault", {"InvalidDBClusterStateFault"}, 450,
        )),
        ("network interfaces", lambda: _enis_detached(180)),
        ("subnet group", lambda: _gone(
            [(
                lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name),
                lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=subnet_group_name),
            )],
            "DBSubnetGroupNotFoundFault", {"InvalidDBSubnetGroupStateFault"}, 90,
        )),
        ("security group", lambda: _gone(
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
            failures.append(f"{what}: {exc!r}")
    if failures:
        raise RuntimeError(f"cross-surface teardown failed for {len(dbs)} cluster(s): {'; '.join(failures)}")


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement on cluster B with a transactionId cluster A issued is refused and writes
    nothing to B, and the transaction still inserts and commits on A.
    Reference: https://docs.aws.amazon.com/rdsdataservice/latest/APIReference/API_ExecuteStatement.html
    """
    a, b = _provision(ctx, "aurora-postgresql", count=2)
    _grade(ctx, a, b)


def _grade(ctx, a, b) -> None:
    table = "sim2real_txn_scope"
    for db in (a, b):
        _sql(ctx, db, f"CREATE TABLE {table} (id INT PRIMARY KEY, src TEXT NOT NULL)")
    txn = _begin(ctx, a)
    committed = False
    try:
        _sql(ctx, a, f"INSERT INTO {table} (id, src) VALUES (1, 'a')", txn=txn)
        code, message = _error(
            lambda: _sql(ctx, b, f"INSERT INTO {table} (id, src) VALUES (2, 'b')", txn=txn)
        )
        assert code == "ValidationException", (
            f"ExecuteStatement on cluster B with cluster A's transactionId must be refused; got "
            f"{code!r}: {message!r}"
        )
        assert message == "Invalid transaction ID", f"unexpected refusal message: {message!r}"
        on_b = _sql(ctx, b, f"SELECT count(*) FROM {table}")["records"]
        assert on_b == [[{"longValue": 0}]], (
            f"the refused statement must write nothing to cluster B; it holds {on_b!r}"
        )
        _sql(ctx, a, f"INSERT INTO {table} (id, src) VALUES (3, 'a')", txn=txn)
        status = _commit(ctx, a, txn)
        committed = True
        assert status == "Transaction Committed", (
            f"the transaction must still commit on its own cluster; got {status!r}"
        )
    finally:
        if not committed:
            _rollback(ctx, a, txn)
    on_a = _sql(ctx, a, f"SELECT id, src FROM {table} ORDER BY id")["records"]
    assert on_a == [
        [{"longValue": 1}, {"stringValue": "a"}],
        [{"longValue": 3}, {"stringValue": "a"}],
    ], f"cluster A must hold exactly the transaction's two rows; got {on_a!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
