"""rds-data-own-cluster-execute-statement-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-data-own-cluster-execute-statement-lifecycle"
GROUP = "data-plane"
SERVICES = ["rds-data", "rds"]

_DB = "simparitydb"
_ENGINE = "aurora-postgresql"
_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]
#: Aurora is a long-budget service class; every poll below is bounded by it.
_RDS_WAIT_S = 2700
#: Each of the three teardowns (instance, cluster, subnet group) gets a third of the 1800 s budget.
_TEARDOWN_WAIT_S = 600
#: Codes that mean the Data API is still coming up on a just-available cluster.
_NOT_READY = ("DatabaseResumingException", "HttpEndpointNotEnabledException")
#: What AWS answers ExecuteStatement on a cluster ARN with no live cluster behind it: the Data API
#: reports the resource as having no HTTP endpoint, and the message names the ARN.
_DEAD_CLUSTER = ("HttpEndpointNotEnabledException", 400)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """The Data API runs SQL against a cluster the check owns: a committed transaction is read
    back, a delete empties the table, and once the cluster is deleted it is gone and unusable."""
    rds = ctx.client("rds")
    rdsdata = ctx.client("rds-data")

    cluster_id = ctx.unique_name("sim2real-behav-rdsd-")
    instance_id = f"{cluster_id}-i"
    subnet_group = _network_db_subnet_group(ctx, rds)
    cluster = rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine=_ENGINE,
        DatabaseName=_DB,
        MasterUsername="simparity",
        ManageMasterUserPassword=True,
        EnableHttpEndpoint=True,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 2.0},
        StorageEncrypted=True,
        Tags=_TAGS,
        DBSubnetGroupName=subnet_group,
    )["DBCluster"]
    ctx.on_cleanup(lambda: _delete_cluster(rds, cluster_id))
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBClusterIdentifier=cluster_id,
        Engine=_ENGINE,
        DBInstanceClass="db.serverless",
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, instance_id))

    expected_arn = f"arn:aws:rds:{ctx.region}:{ctx.account}:cluster:{cluster_id}"
    assert cluster["DBClusterArn"] == expected_arn, (
        f"DBClusterArn: expected {expected_arn!r}, got {cluster.get('DBClusterArn')!r}"
    )
    resource_arn = cluster["DBClusterArn"]
    secret_arn = cluster["MasterUserSecret"]["SecretArn"]

    _poll(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0][
            "DBInstanceStatus"
        ],
        lambda s: s == "available",
        what=f"instance {instance_id} available",
    )
    _poll(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]["Status"],
        lambda s: s == "available",
        what=f"cluster {cluster_id} available",
    )
    _wait_data_api_ready(rdsdata, resource_arn, secret_arn)

    def sql(statement, **kw):
        return rdsdata.execute_statement(
            resourceArn=resource_arn, secretArn=secret_arn, database=_DB, sql=statement, **kw
        )

    sql("CREATE TABLE t (id int primary key, name text)")
    tx = rdsdata.begin_transaction(resourceArn=resource_arn, secretArn=secret_arn, database=_DB)[
        "transactionId"
    ]
    sql("INSERT INTO t (id, name) VALUES (1, 'alice')", transactionId=tx)
    committed = rdsdata.commit_transaction(
        resourceArn=resource_arn, secretArn=secret_arn, transactionId=tx
    )
    assert committed.get("transactionStatus") == "Transaction Committed", (
        f"CommitTransaction: expected 'Transaction Committed', got "
        f"{committed.get('transactionStatus')!r}"
    )

    read = sql("SELECT id, name FROM t WHERE id = 1", includeResultMetadata=True)
    assert read["records"] == [[{"longValue": 1}, {"stringValue": "alice"}]], (
        f"the committed row must read back as id=1, name='alice'; got {read.get('records')!r}"
    )
    names = [c["name"] for c in read["columnMetadata"]]
    assert names == ["id", "name"], f"columnMetadata names: expected ['id', 'name'], got {names!r}"

    deleted = sql("DELETE FROM t WHERE id = 1")
    assert deleted["numberOfRecordsUpdated"] == 1, (
        f"DELETE of the one row must update 1 record, got {deleted.get('numberOfRecordsUpdated')!r}"
    )
    after = sql("SELECT id, name FROM t WHERE id = 1")
    assert after["records"] == [], f"the deleted row still reads back: {after.get('records')!r}"

    # Delete the instance, then the cluster, and prove the cluster gone and unusable.
    _delete_instance(rds, instance_id, wait_s=_RDS_WAIT_S)
    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    _poll(
        lambda: _cluster_gone(rds, cluster_id),
        lambda gone: gone,
        what=f"cluster {cluster_id} DBClusterNotFoundFault",
    )
    code, status, message = _client_error(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
    )
    assert (code, status) == ("DBClusterNotFoundFault", 404), (
        f"describe deleted cluster: expected ('DBClusterNotFoundFault', 404), got ({code!r}, {status})"
    )
    expected_message = f"DBCluster {cluster_id} not found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    listed = rds.describe_db_clusters(
        Filters=[{"Name": "db-cluster-id", "Values": [cluster_id]}]
    )["DBClusters"]
    assert listed == [], f"filtered DescribeDBClusters still lists the deleted cluster: {len(listed)}"

    code, status, message = _client_error(
        lambda: rdsdata.execute_statement(
            resourceArn=resource_arn, secretArn=secret_arn, sql="SELECT 1"
        )
    )
    assert (code, status) == _DEAD_CLUSTER, (
        f"ExecuteStatement on the deleted cluster: expected {_DEAD_CLUSTER}, got ({code!r}, {status})"
    )
    code, status, message = _client_error(
        lambda: rds.modify_db_cluster(DBClusterIdentifier=cluster_id, DeletionProtection=False)
    )
    assert (code, status) == ("DBClusterNotFoundFault", 404), (
        f"modify deleted cluster: expected ('DBClusterNotFoundFault', 404), got ({code!r}, {status})"
    )
    expected_message = "DBCluster not found"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


def _poll(fn, pred, *, what, timeout_s=_RDS_WAIT_S, interval_s=15):
    """Poll fn() until pred(value); raise naming the last value when the deadline passes."""
    deadline = time.monotonic() + timeout_s
    while True:
        val = fn()
        if pred(val):
            return val
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: not reached within {timeout_s}s; last {val!r}")
        time.sleep(interval_s)


def _wait_data_api_ready(rdsdata, resource_arn, secret_arn, timeout_s=900):
    """SELECT 1 against the check's database until it succeeds; only the Data API's not-yet-ready
    codes are retried. Without ``database`` PostgreSQL connects to one named after the admin user name."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rdsdata.execute_statement(resourceArn=resource_arn, secretArn=secret_arn, database=_DB, sql="SELECT 1")
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in _NOT_READY or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _client_error(fn) -> tuple[str, int, str]:
    """(code, HTTP status, message) of the ClientError fn() raises; AssertionError on success."""
    try:
        resp = fn()
    except ClientError as exc:
        return (
            exc.response["Error"]["Code"],
            exc.response["ResponseMetadata"]["HTTPStatusCode"],
            exc.response["Error"].get("Message") or "",
        )
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp!r}")


def _cluster_gone(rds, cluster_id) -> bool:
    try:
        rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DBClusterNotFoundFault":
            return True
        raise
    return False


def _instance_gone(rds, instance_id) -> bool:
    try:
        rds.describe_db_instances(DBInstanceIdentifier=instance_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DBInstanceNotFound":
            return True
        raise
    return False


def _delete_instance(rds, instance_id, wait_s=_TEARDOWN_WAIT_S) -> None:
    """Delete the cluster's instance and wait until it is gone; InvalidDBInstanceState is retried
    every 2 s to the deadline and an absent instance is fine."""
    deadline = time.monotonic() + wait_s
    while True:
        try:
            rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "DBInstanceNotFound":
                return
            if code != "InvalidDBInstanceState" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    _poll(lambda: _instance_gone(rds, instance_id), lambda gone: gone,
          what=f"instance {instance_id} deleted",
          timeout_s=max(1.0, deadline - time.monotonic()), interval_s=2)


def _delete_cluster(rds, cluster_id) -> None:
    """Teardown: delete the cluster with no final snapshot and wait until it is gone;
    InvalidDBClusterStateFault (a member still deleting) is retried every 2 s to the deadline."""
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        try:
            rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "DBClusterNotFoundFault":
                return
            if code != "InvalidDBClusterStateFault" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    _poll(lambda: _cluster_gone(rds, cluster_id), lambda gone: gone,
          what=f"cluster {cluster_id} deleted",
          timeout_s=max(1.0, deadline - time.monotonic()), interval_s=2)


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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=_TEARDOWN_WAIT_S,
                          interval_s=2.0):
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
