"""idle-transaction-write-is-rolled-back-and-rollback-on-expired-id-refused."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "idle-transaction-write-is-rolled-back-and-rollback-on-expired-id-refused"
GROUP = "state"
SERVICES = ["ec2", "rds", "rds-data"]

_TABLE = "sim2real_behav_idle_txn_writes"


# timing:real-time — ttl: 180 s https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/data-api.html
@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A write inside a transaction left idle past the documented 3-minute timeout is
    automatically rolled back, and RollbackTransaction on the expired id is itself refused."""
    db = _provision_cluster(ctx)
    rdsdata = ctx.client("rds-data")

    rdsdata.execute_statement(
        resourceArn=db["resourceArn"], secretArn=db["secretArn"], database=db["database"],
        sql=f"CREATE TABLE {_TABLE} (id INT PRIMARY KEY, v VARCHAR(50))",
    )

    def autocommit_ids():
        resp = rdsdata.execute_statement(
            resourceArn=db["resourceArn"], secretArn=db["secretArn"], database=db["database"],
            sql=f"SELECT id FROM {_TABLE} ORDER BY id",
        )
        return [r[0]["longValue"] for r in resp.get("records") or []]

    # Positive control: an ordinary transaction commits and its row is visible outside it.
    control_txn = rdsdata.begin_transaction(
        resourceArn=db["resourceArn"], secretArn=db["secretArn"], database=db["database"]
    )["transactionId"]
    rdsdata.execute_statement(
        resourceArn=db["resourceArn"], secretArn=db["secretArn"], database=db["database"],
        transactionId=control_txn,
        sql=f"INSERT INTO {_TABLE} (id, v) VALUES (1, 'committed')",
    )
    control_commit = rdsdata.commit_transaction(
        resourceArn=db["resourceArn"], secretArn=db["secretArn"], transactionId=control_txn
    )
    assert control_commit["transactionStatus"] == "Transaction Committed", (
        f"positive control: expected 'Transaction Committed', got {control_commit['transactionStatus']!r}"
    )
    assert autocommit_ids() == [1], (
        f"positive control: committed row must be visible outside its transaction; got {autocommit_ids()!r}"
    )

    # A second transaction writes a row, then is left idle with no intervening call that
    # references it (any such read would reset the idle clock) until the documented 3-minute
    # (180 s) inactivity window has passed.
    idle_txn = rdsdata.begin_transaction(
        resourceArn=db["resourceArn"], secretArn=db["secretArn"], database=db["database"]
    )["transactionId"]
    assert idle_txn != control_txn, (
        f"a second BeginTransaction must return a new transactionId; both are {control_txn!r}"
    )
    in_txn_insert = rdsdata.execute_statement(
        resourceArn=db["resourceArn"], secretArn=db["secretArn"], database=db["database"],
        transactionId=idle_txn,
        sql=f"INSERT INTO {_TABLE} (id, v) VALUES (2, 'idle-doomed')",
    )
    assert in_txn_insert["numberOfRecordsUpdated"] == 1, (
        f"the write inside idle_txn must be accepted before the idle wait; got "
        f"numberOfRecordsUpdated={in_txn_insert['numberOfRecordsUpdated']!r}"
    )
    in_txn_read = rdsdata.execute_statement(
        resourceArn=db["resourceArn"], secretArn=db["secretArn"], database=db["database"],
        transactionId=idle_txn,
        sql=f"SELECT id FROM {_TABLE} WHERE id = 2",
    )
    in_txn_ids = [r[0]["longValue"] for r in in_txn_read.get("records") or []]
    assert in_txn_ids == [2], (
        f"the write must be visible inside idle_txn before expiry; got {in_txn_ids!r}"
    )

    idle_deadline = time.monotonic() + 260
    while time.monotonic() < idle_deadline:
        time.sleep(min(10, idle_deadline - time.monotonic()))

    rollback_error = _refusal(
        lambda: rdsdata.rollback_transaction(
            resourceArn=db["resourceArn"], secretArn=db["secretArn"], transactionId=idle_txn
        )
    )
    assert rollback_error.get("Code") == _IDLE_REFUSAL[0], (
        f"RollbackTransaction on an idle-expired txn: expected {_IDLE_REFUSAL[0]!r}, got {rollback_error!r}"
    )
    assert rollback_error.get("Message") == _IDLE_REFUSAL[1], (
        f"unexpected refusal message: {rollback_error.get('Message')!r}"
    )

    after_ids = autocommit_ids()
    assert after_ids == [1], (
        f"the idle transaction's write (id 2) must have been rolled back automatically, leaving "
        f"only the committed row (id 1); an autocommit SELECT found ids {after_ids!r}"
    )

    # A further positive control after the idle transaction: the cluster and table remain
    # otherwise functional for a brand-new transaction.
    after_txn = rdsdata.begin_transaction(
        resourceArn=db["resourceArn"], secretArn=db["secretArn"], database=db["database"]
    )["transactionId"]
    rdsdata.execute_statement(
        resourceArn=db["resourceArn"], secretArn=db["secretArn"], database=db["database"],
        transactionId=after_txn,
        sql=f"INSERT INTO {_TABLE} (id, v) VALUES (3, 'after-idle')",
    )
    after_commit = rdsdata.commit_transaction(
        resourceArn=db["resourceArn"], secretArn=db["secretArn"], transactionId=after_txn
    )
    assert after_commit["transactionStatus"] == "Transaction Committed", (
        f"positive control after the idle txn: expected 'Transaction Committed', got "
        f"{after_commit['transactionStatus']!r}"
    )
    assert autocommit_ids() == [1, 3], (
        f"the account must still accept and commit ordinary writes after the idle-expired "
        f"transaction; got {autocommit_ids()!r}"
    )


_IDLE_REFUSAL = (
    "TransactionNotFoundException",
    "INVALID_ARGUMENT: Transaction error: transaction has been terminated due to an idleness",
)


def _refusal(fn):
    """The botocore Error dict (Code, Message) fn() raised. An unexpected SUCCESS raises
    AssertionError: a target that ACCEPTS a call real AWS refuses must fail loudly, not as a
    code mismatch against a falsy sentinel."""
    try:
        resp = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"the call was ACCEPTED and returned {resp!r}")


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
                time.sleep(10)
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
    fails; then the teardown raises naming each step that failed.
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
