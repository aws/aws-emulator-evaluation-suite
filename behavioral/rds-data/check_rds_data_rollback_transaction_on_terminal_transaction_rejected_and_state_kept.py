"""rds-data-rollback-transaction-on-terminal-transaction-rejected-and-state-kept."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-data-rollback-transaction-on-terminal-transaction-rejected-and-state-kept"
GROUP = "state"
SERVICES = ["rds-data"]

_DB = "simparitydb"
_USER = "sim2real"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

# CreateDBCluster to the first accepted Data API statement measures roughly 500 s on AWS; these
# ceilings leave about 2.4x headroom and make up this check's declared deadline.
_MEMBER_WAIT_S = 1200
_CLUSTER_WAIT_S = 600
_SECRET_WAIT_S = 300
_DATA_API_WAIT_S = 300
_TEARDOWN_WAIT_S = 900


def _poll(fn, pred, *, timeout_s, interval_s=15):
    """Poll fn() until pred(value) or the deadline; returns the last value seen."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _instance(rds, inst_id):
    """DescribeDBInstances for one id, or None when it no longer exists."""
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
            return None
        raise


def _cluster(rds, cl_id):
    """DescribeDBClusters for one id, or None when it no longer exists."""
    try:
        return rds.describe_db_clusters(DBClusterIdentifier=cl_id)["DBClusters"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBClusterNotFoundFault":
            return None
        raise


def _delete_instance(rds, inst_id):
    """Delete a cluster member, retrying while it is in a non-deletable state, and wait for it
    to vanish; a cluster with a remaining member cannot be deleted."""
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        inst = _instance(rds, inst_id)
        if inst is None:
            return
        if inst.get("DBInstanceStatus") == "deleting":
            break
        try:
            rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
                return
            if time.monotonic() >= deadline:
                raise
            time.sleep(20)
    left = _poll(lambda: _instance(rds, inst_id), lambda i: i is None,
                 timeout_s=_TEARDOWN_WAIT_S, interval_s=20)
    assert left is None, (
        f"cluster member {inst_id} still exists {_TEARDOWN_WAIT_S}s after DeleteDBInstance; "
        f"status {left.get('DBInstanceStatus')!r}"
    )


def _delete_cluster(rds, cl_id):
    """Delete the cluster with no final snapshot, retrying while the member drains, then wait
    for it to vanish; the managed admin-user secret is deleted with the cluster."""
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        cluster = _cluster(rds, cl_id)
        if cluster is None:
            return
        if cluster.get("Status") == "deleting":
            break
        try:
            rds.delete_db_cluster(DBClusterIdentifier=cl_id, SkipFinalSnapshot=True)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DBClusterNotFoundFault":
                return
            if time.monotonic() >= deadline:
                raise
            time.sleep(20)
    left = _poll(lambda: _cluster(rds, cl_id), lambda c: c is None,
                 timeout_s=_TEARDOWN_WAIT_S, interval_s=20)
    assert left is None, (
        f"cluster {cl_id} still exists {_TEARDOWN_WAIT_S}s after DeleteDBCluster; status "
        f"{left.get('Status')!r}"
    )


def _teardown(rds, created):
    """Delete whatever _provision_data_api_cluster created, member first; the cluster delete is
    attempted even when the member delete fails, and the first failure is re-raised."""
    try:
        if "member" in created:
            _delete_instance(rds, created["member"])
    finally:
        if "cluster" in created:
            _delete_cluster(rds, created["cluster"])


def _network_db_subnet_group(ctx, rds) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name),
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


def _provision_data_api_cluster(ctx, rds, data, created):
    """An aurora-postgresql Serverless v2 cluster with the Data API and an RDS-managed secret;
    every id is recorded in `created` as soon as it exists. Returns (cluster_arn, secret_arn)."""
    versions = rds.describe_db_engine_versions(
        Engine="aurora-postgresql", DefaultOnly=True
    ).get("DBEngineVersions", [])
    assert versions, (
        "no aurora-postgresql engine version is orderable in "
        f"{ctx.region!r} — the Data API cannot be exercised here"
    )
    version = versions[0]["EngineVersion"]

    subnet_group = _network_db_subnet_group(ctx, rds)
    cl_id = ctx.unique_name("sim2real-behav-rdc-")
    rds.create_db_cluster(
        DBClusterIdentifier=cl_id,
        Engine="aurora-postgresql",
        EngineVersion=version,
        MasterUsername=_USER,
        ManageMasterUserPassword=True,
        DatabaseName=_DB,
        EnableHttpEndpoint=True,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 4.0},
        BackupRetentionPeriod=1,
        DeletionProtection=False,
        DBSubnetGroupName=subnet_group,
        Tags=_MANAGED_TAGS,
    )
    created["cluster"] = cl_id
    ctx.on_cleanup(lambda: _delete_cluster(rds, cl_id))

    member_id = ctx.unique_name("sim2real-behav-rdw-")
    rds.create_db_instance(
        DBInstanceIdentifier=member_id,
        DBClusterIdentifier=cl_id,
        Engine="aurora-postgresql",
        DBInstanceClass="db.serverless",
        Tags=_MANAGED_TAGS,
    )
    created["member"] = member_id
    ctx.on_cleanup(lambda: _delete_instance(rds, member_id))

    member = _poll(
        lambda: _instance(rds, member_id),
        lambda i: i is not None and i.get("DBInstanceStatus") == "available",
        timeout_s=_MEMBER_WAIT_S,
    )
    assert member is not None and member.get("DBInstanceStatus") == "available", (
        f"the writer {member_id} did not reach 'available' within {_MEMBER_WAIT_S}s; last "
        f"status {(member or {}).get('DBInstanceStatus')!r}"
    )

    cluster = _poll(
        lambda: _cluster(rds, cl_id),
        lambda c: c is not None and c.get("Status") == "available",
        timeout_s=_CLUSTER_WAIT_S,
    )
    assert cluster is not None and cluster.get("Status") == "available", (
        f"cluster {cl_id} did not reach 'available'; last "
        f"{(cluster or {}).get('Status')!r}"
    )
    assert cluster.get("HttpEndpointEnabled") is True, (
        "the cluster must report HttpEndpointEnabled=True after EnableHttpEndpoint=True; got "
        f"{cluster.get('HttpEndpointEnabled')!r}"
    )

    secret_arn = (cluster.get("MasterUserSecret") or {}).get("SecretArn")
    assert secret_arn, (
        "ManageMasterUserPassword must publish MasterUserSecret.SecretArn; got "
        f"MasterUserSecret={cluster.get('MasterUserSecret')!r}"
    )
    secret_status = _poll(
        lambda: ((_cluster(rds, cl_id) or {}).get("MasterUserSecret") or {}).get(
            "SecretStatus"
        ),
        lambda s: s == "active",
        timeout_s=_SECRET_WAIT_S,
        interval_s=20,
    )
    assert secret_status == "active", (
        f"the managed MasterUserSecret must become 'active'; it is {secret_status!r}"
    )

    cluster_arn = cluster["DBClusterArn"]
    # Any refusal is retried to the deadline, then reported verbatim: a cold endpoint must not
    # discard the provision, and no error-code allowlist can hide a persistent refusal.
    deadline = time.monotonic() + _DATA_API_WAIT_S
    warm = None
    while time.monotonic() < deadline:
        try:
            data.execute_statement(resourceArn=cluster_arn, secretArn=secret_arn,
                                   database=_DB, sql="SELECT 1")
            warm = True
            break
        except ClientError as exc:
            warm = exc
            time.sleep(2)
    assert warm is True, (
        f"the Data API never accepted a trivial statement on {cluster_arn} within "
        f"{_DATA_API_WAIT_S}s; the last refusal was {warm!r}"
    )
    return cluster_arn, secret_arn


def _refusal(fn):
    """The ClientError fn() raised; raises AssertionError if the call succeeded instead."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(
        f"the call was ACCEPTED and returned "
        f"{ {k: v for k, v in resp.items() if k != 'ResponseMetadata'} !r}"
    )


def _code(exc) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _message(exc) -> str:
    return exc.response.get("Error", {}).get("Message", "")


def _status(exc) -> int | None:
    return exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")

_TABLE = "sim2real_behav_terminal_txn_rollback"
_COMMITTED = [(1, "committed")]
_TERMINATED_CODE = "TransactionNotFoundException"
_TERMINATED_STATUS = 404
_TERMINATED_MESSAGE = (
    "INVALID_ARGUMENT: Transaction error: one previous call resulted in a termination of your "
    "transaction"
)


def _assert_terminated(exc, what) -> None:
    """The refusal AWS returns for a transactionId that is already committed or rolled back."""
    assert _status(exc) == _TERMINATED_STATUS, (
        f"{what} must be refused with HTTP {_TERMINATED_STATUS}; got {_status(exc)!r} "
        f"({_code(exc)!r}: {_message(exc)!r})"
    )
    assert _code(exc) == _TERMINATED_CODE, (
        f"{what} must be refused with {_TERMINATED_CODE}; got {_code(exc)!r}: {_message(exc)!r}"
    )
    assert exc.response["Error"]["Message"] == _TERMINATED_MESSAGE, (
        f"{what} must carry the message {_TERMINATED_MESSAGE!r}; got {_message(exc)!r}"
    )


def _grade(data, resource_arn, secret_arn) -> None:
    """Every assertion this check makes, against an already-provisioned Data API cluster."""

    def ex(sql, **kw):
        return data.execute_statement(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB, sql=sql, **kw)

    def rows(**kw):
        records = ex(f"SELECT id, v FROM {_TABLE} ORDER BY id", **kw).get("records") or []
        return [(r[0]["longValue"], r[1]["stringValue"]) for r in records]

    def begin():
        txn = data.begin_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                     database=_DB).get("transactionId")
        assert isinstance(txn, str) and txn, (
            f"BeginTransaction must return a non-empty transactionId; got {txn!r}"
        )
        return txn

    def rollback(txn):
        return data.rollback_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                         transactionId=txn)

    ex(f"CREATE TABLE {_TABLE} (id int PRIMARY KEY, v text NOT NULL)")

    committed_txn = begin()
    ex(f"INSERT INTO {_TABLE} (id, v) VALUES (1, 'committed')", transactionId=committed_txn)
    commit = data.commit_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                     transactionId=committed_txn)
    assert commit.get("transactionStatus") == "Transaction Committed", (
        f"CommitTransaction must report transactionStatus 'Transaction Committed'; got "
        f"{commit.get('transactionStatus')!r}"
    )
    assert rows() == _COMMITTED, (
        f"the committed row must be readable outside the transaction; table holds {rows()!r}"
    )

    _assert_terminated(_refusal(lambda: rollback(committed_txn)),
                       "RollbackTransaction on a committed transactionId")
    survived = rows()
    assert survived == _COMMITTED, (
        f"a refused RollbackTransaction must not undo the committed write; expected "
        f"{_COMMITTED!r}, got {survived!r}"
    )

    rolled_back_txn = begin()
    assert rolled_back_txn != committed_txn, (
        f"a second BeginTransaction must return a new transactionId; both are {committed_txn!r}"
    )
    ex(f"INSERT INTO {_TABLE} (id, v) VALUES (2, 'rolled-back')", transactionId=rolled_back_txn)
    in_txn = rows(transactionId=rolled_back_txn)
    assert in_txn == _COMMITTED + [(2, "rolled-back")], (
        f"inside the second transaction its own write must be visible next to the committed "
        f"row; got {in_txn!r}"
    )
    first = rollback(rolled_back_txn)
    assert first.get("transactionStatus") == "Rollback complete", (
        f"the first RollbackTransaction must report transactionStatus 'Rollback complete'; got "
        f"{first.get('transactionStatus')!r}"
    )

    _assert_terminated(_refusal(lambda: rollback(rolled_back_txn)),
                       "a second RollbackTransaction on a rolled-back transactionId")
    _assert_terminated(
        _refusal(lambda: ex(f"INSERT INTO {_TABLE} (id, v) VALUES (3, 'dead-transaction')",
                            transactionId=rolled_back_txn)),
        "ExecuteStatement with a rolled-back transactionId",
    )

    final = rows()
    assert final == _COMMITTED, (
        f"only the committed row may remain: the rolled-back write (id 2) and the refused write "
        f"on the dead transaction (id 3) must both be absent; expected {_COMMITTED!r}, got "
        f"{final!r}"
    )


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """RollbackTransaction on a committed or already rolled-back transactionId is refused with
    TransactionNotFoundException (404), a rolled-back id cannot carry further statements, and
    neither refusal changes table contents."""
    rds = ctx.client("rds")
    data = ctx.client("rds-data")
    created: dict[str, str] = {}
    # Teardown runs inline: deleting an RDS member and cluster takes minutes, longer than the
    # cleanup budget. The cleanups registered at creation are the backstop.
    try:
        resource_arn, secret_arn = _provision_data_api_cluster(ctx, rds, data, created)
        _grade(data, resource_arn, secret_arn)
    finally:
        _teardown(rds, created)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
