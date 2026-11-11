"""rds-data-batch-execute-statement-in-transaction-discarded-by-rollback-and-persisted-by-commit."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "rds-data-batch-execute-statement-in-transaction-discarded-by-rollback-and-persisted-by-commit"
)
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(fn, pred, *, timeout_s, interval_s=2):
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


def _delete_instance(ctx, rds, inst_id):
    """Delete a cluster member, retrying while it is in a non-deletable state, and wait for it
    to vanish; a cluster with a remaining member cannot be deleted."""
    # A registered cleanup passes ctx=None and waits the full _TEARDOWN_WAIT_S at each step.
    deadline = time.monotonic() + (_TEARDOWN_WAIT_S if ctx is None
                                   else _budget_s(ctx, _TEARDOWN_WAIT_S))
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
                if ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(
                        f"DeleteDBInstance {inst_id}: the run budget ended first; not graded"
                    ) from exc
                raise
            time.sleep(2)
    left = _poll(lambda: _instance(rds, inst_id), lambda i: i is None,
                 timeout_s=(_TEARDOWN_WAIT_S if ctx is None
                            else _budget_s(ctx, _TEARDOWN_WAIT_S)))
    if left is not None and ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"cluster member {inst_id} deleted: the run budget ended first; not graded")
    assert left is None, (
        f"cluster member {inst_id} still exists {_TEARDOWN_WAIT_S}s after DeleteDBInstance; "
        f"status {left.get('DBInstanceStatus')!r}"
    )


def _delete_cluster(ctx, rds, cl_id):
    """Delete the cluster with no final snapshot, retrying while the member drains, then wait
    for it to vanish; the managed admin-user secret is deleted with the cluster."""
    # A registered cleanup passes ctx=None and waits the full _TEARDOWN_WAIT_S at each step.
    deadline = time.monotonic() + (_TEARDOWN_WAIT_S if ctx is None
                                   else _budget_s(ctx, _TEARDOWN_WAIT_S))
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
                if ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(
                        f"DeleteDBCluster {cl_id}: the run budget ended first; not graded"
                    ) from exc
                raise
            time.sleep(2)
    left = _poll(lambda: _cluster(rds, cl_id), lambda c: c is None,
                 timeout_s=(_TEARDOWN_WAIT_S if ctx is None
                            else _budget_s(ctx, _TEARDOWN_WAIT_S)))
    if left is not None and ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"cluster {cl_id} deleted: the run budget ended first; not graded")
    assert left is None, (
        f"cluster {cl_id} still exists {_TEARDOWN_WAIT_S}s after DeleteDBCluster; status "
        f"{left.get('Status')!r}"
    )


def _teardown(ctx, rds, created):
    """Delete whatever _provision_data_api_cluster created, member first; the cluster delete is
    attempted even when the member delete fails, and the first failure is re-raised."""
    try:
        if "member" in created:
            _delete_instance(ctx, rds, created["member"])
    finally:
        if "cluster" in created:
            _delete_cluster(ctx, rds, created["cluster"])


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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=2.0):
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
    ctx.on_cleanup(lambda: _delete_cluster(None, rds, cl_id))

    member_id = ctx.unique_name("sim2real-behav-rdw-")
    rds.create_db_instance(
        DBInstanceIdentifier=member_id,
        DBClusterIdentifier=cl_id,
        Engine="aurora-postgresql",
        DBInstanceClass="db.serverless",
        Tags=_MANAGED_TAGS,
    )
    created["member"] = member_id
    ctx.on_cleanup(lambda: _delete_instance(None, rds, member_id))

    member = _poll(
        lambda: _instance(rds, member_id),
        lambda i: i is not None and i.get("DBInstanceStatus") == "available",
        timeout_s=_budget_s(ctx, _MEMBER_WAIT_S),
    )
    if not (member is not None and member.get("DBInstanceStatus") == "available") and _budget_spent(ctx):
        raise TimeoutError(f"writer {member_id} available: the run budget ended first; not graded")
    assert member is not None and member.get("DBInstanceStatus") == "available", (
        f"the writer {member_id} did not reach 'available' within {_MEMBER_WAIT_S}s; last "
        f"status {(member or {}).get('DBInstanceStatus')!r}"
    )

    cluster = _poll(
        lambda: _cluster(rds, cl_id),
        lambda c: c is not None and c.get("Status") == "available",
        timeout_s=_budget_s(ctx, _CLUSTER_WAIT_S),
    )
    if not (cluster is not None and cluster.get("Status") == "available") and _budget_spent(ctx):
        raise TimeoutError(f"cluster {cl_id} available: the run budget ended first; not graded")
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
        timeout_s=_budget_s(ctx, _SECRET_WAIT_S),
    )
    if secret_status != "active" and _budget_spent(ctx):
        raise TimeoutError("managed master-user secret active: the run budget ended first; not graded")
    assert secret_status == "active", (
        f"the managed master-user secret must become 'active'; it is {secret_status!r}"
    )

    cluster_arn = cluster["DBClusterArn"]
    # Any refusal is retried to the deadline, then reported verbatim: a cold endpoint must not
    # discard the provision, and no error-code allowlist can hide a persistent refusal.
    deadline = time.monotonic() + _budget_s(ctx, _DATA_API_WAIT_S)
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
    if warm is not True and _budget_spent(ctx):
        raise TimeoutError(f"Data API first statement on {cluster_arn}: the run budget ended first; not graded")
    assert warm is True, (
        f"the Data API never accepted a trivial statement on {cluster_arn} within "
        f"{_DATA_API_WAIT_S}s; the last refusal was {warm!r}"
    )
    return cluster_arn, secret_arn

_TABLE = "sim2real_behav_batch_txn_rollback"
_BASELINE = [(1, "baseline")]


def _grade(data, resource_arn, secret_arn) -> None:
    """Every assertion this check makes, against an already-provisioned Data API cluster."""

    def ex(sql, **kw):
        return data.execute_statement(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB, sql=sql, **kw)

    def rows(**kw):
        records = ex(f"SELECT id, v FROM {_TABLE} ORDER BY id", **kw).get("records") or []
        return [(r[0]["longValue"], r[1]["stringValue"]) for r in records]

    ex(f"CREATE TABLE {_TABLE} (id int PRIMARY KEY, v text NOT NULL)")
    ex(f"INSERT INTO {_TABLE} (id, v) VALUES (1, 'baseline')")
    assert rows() == _BASELINE, (
        f"the committed baseline row must be readable before the transaction opens; table holds "
        f"{rows()!r}"
    )

    txn = data.begin_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                 database=_DB).get("transactionId")
    assert isinstance(txn, str) and txn, (
        f"BeginTransaction must return a non-empty transactionId; got {txn!r}"
    )

    batch_ids = [10, 11, 12]
    batch = data.batch_execute_statement(
        resourceArn=resource_arn, secretArn=secret_arn, database=_DB, transactionId=txn,
        sql=f"INSERT INTO {_TABLE} (id, v) VALUES (:id, :v)",
        parameterSets=[[{"name": "id", "value": {"longValue": i}},
                        {"name": "v", "value": {"stringValue": f"batch-{i}"}}]
                       for i in batch_ids],
    )
    assert batch.get("updateResults") == [{"generatedFields": []}] * len(batch_ids), (
        f"a BatchExecuteStatement bound to a transaction must return one updateResults entry per "
        f"parameter set; got {batch.get('updateResults')!r}"
    )

    expected_in_txn = _BASELINE + [(i, f"batch-{i}") for i in batch_ids]
    in_txn = rows(transactionId=txn)
    assert in_txn == expected_in_txn, (
        f"inside the transaction a read must see the baseline row plus every batch row; expected "
        f"{expected_in_txn!r}, got {in_txn!r}"
    )
    outside = rows()
    assert outside == _BASELINE, (
        f"a read outside the transaction must not see the uncommitted batch rows; expected "
        f"{_BASELINE!r}, got {outside!r}"
    )

    rollback = data.rollback_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                         transactionId=txn)
    assert rollback.get("transactionStatus") == "Rollback complete", (
        f"RollbackTransaction must report transactionStatus 'Rollback complete'; got "
        f"{rollback.get('transactionStatus')!r}"
    )

    after = rows()
    assert after == _BASELINE, (
        f"after RollbackTransaction none of the batch rows {batch_ids!r} may exist and the "
        f"baseline row must be unchanged; expected {_BASELINE!r}, got {after!r}"
    )

    commit_txn = data.begin_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                        database=_DB).get("transactionId")
    assert isinstance(commit_txn, str) and commit_txn and commit_txn != txn, (
        f"BeginTransaction must return a non-empty transactionId distinct from the rolled-back "
        f"transaction {txn!r}; got {commit_txn!r}"
    )

    commit_ids = [20, 21, 22]
    commit_batch = data.batch_execute_statement(
        resourceArn=resource_arn, secretArn=secret_arn, database=_DB, transactionId=commit_txn,
        sql=f"INSERT INTO {_TABLE} (id, v) VALUES (:id, :v)",
        parameterSets=[[{"name": "id", "value": {"longValue": i}},
                        {"name": "v", "value": {"stringValue": f"commit-{i}"}}]
                       for i in commit_ids],
    )
    assert commit_batch.get("updateResults") == [{"generatedFields": []}] * len(commit_ids), (
        f"a BatchExecuteStatement bound to the transaction that will be committed must return one "
        f"updateResults entry per parameter set; got {commit_batch.get('updateResults')!r}"
    )

    before_commit = rows()
    assert before_commit == _BASELINE, (
        f"before CommitTransaction a read outside the transaction must still see only the baseline "
        f"row; expected {_BASELINE!r}, got {before_commit!r}"
    )

    commit = data.commit_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                     transactionId=commit_txn)
    assert commit.get("transactionStatus") == "Transaction Committed", (
        f"CommitTransaction must report transactionStatus 'Transaction Committed'; got "
        f"{commit.get('transactionStatus')!r}"
    )

    expected_final = _BASELINE + [(i, f"commit-{i}") for i in commit_ids]
    final = rows()
    assert final == expected_final, (
        f"after CommitTransaction a read outside any transaction must see every row the committed "
        f"batch wrote {commit_ids!r} and still none of the rolled-back batch rows {batch_ids!r}; "
        f"expected {expected_final!r}, got {final!r}"
    )


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A BatchExecuteStatement bound to a transactionId writes only inside that transaction.
    RollbackTransaction discards every row such a batch wrote, while a batch finalised with
    CommitTransaction is readable outside any transaction and leaves the discarded rows absent."""
    rds = ctx.client("rds")
    data = ctx.client("rds-data")
    created: dict[str, str] = {}
    # Teardown runs inline: deleting an RDS member and cluster takes minutes, longer than the
    # runner's cleanup budget. The cleanups registered at creation are the backstop.
    try:
        resource_arn, secret_arn = _provision_data_api_cluster(ctx, rds, data, created)
        _grade(data, resource_arn, secret_arn)
    finally:
        _teardown(ctx, rds, created)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
