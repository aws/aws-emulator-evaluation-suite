"""data-api-transaction-rollback-isolation."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-api-transaction-rollback-isolation"
GROUP = 'data_api'
SERVICES = ['rds']

_DB = "simparitydb"
_USER = "sim2real"
_TABLE = "sim2real_dp_txn"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


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


def _wait_instance_available(rds, inst_id, *, timeout_s=2100):
    """Poll a DB instance to 'available' and return its describe payload."""
    inst = _poll(
        lambda: _instance(rds, inst_id),
        lambda i: i is not None and i.get("DBInstanceStatus") == "available",
        timeout_s=timeout_s,
    )
    assert inst is not None, f"DB instance {inst_id} vanished while waiting for 'available'"
    assert inst["DBInstanceStatus"] == "available", (
        f"DB instance {inst_id} did not reach 'available' within {timeout_s}s; "
        f"last status {inst['DBInstanceStatus']!r}"
    )
    return inst


def _delete_instance(rds, inst_id, *, wait_s=0):
    """Delete a cluster member with no final snapshot, retried while it is in a state that
    refuses the delete; optionally wait until it is gone."""
    deadline = time.monotonic() + max(wait_s, 300)
    while True:
        try:
            rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "DBInstanceNotFound":
                return
            if code != "InvalidDBInstanceState" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    if wait_s:
        left = _poll(lambda: _instance(rds, inst_id), lambda i: i is None,
                     timeout_s=max(0.0, deadline - time.monotonic()), interval_s=2)
        if left is not None:
            raise RuntimeError(
                f"cluster member {inst_id} still exists {wait_s}s after DeleteDBInstance"
            )


def _delete_cluster(rds, cl_id, *, wait_s=600):
    """Cluster teardown with no final snapshot, retried while the member drains."""
    deadline = time.monotonic() + wait_s
    while True:
        try:
            rds.delete_db_cluster(DBClusterIdentifier=cl_id, SkipFinalSnapshot=True)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "DBClusterNotFoundFault":
                return
            # InvalidDBClusterStateFault while the member is still draining: retry.
            if code != "InvalidDBClusterStateFault" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    if wait_s:
        left = _poll(lambda: _cluster(rds, cl_id), lambda c: c is None,
                     timeout_s=max(0.0, deadline - time.monotonic()), interval_s=2)
        if left is not None:
            raise RuntimeError(f"cluster {cl_id} still exists {wait_s}s after DeleteDBCluster")


def _serverless_v2_version(rds):
    """A default aurora-postgresql version; raises AssertionError when none is orderable."""
    try:
        versions = rds.describe_db_engine_versions(
            Engine="aurora-postgresql", DefaultOnly=True
        ).get("DBEngineVersions", [])
    except ClientError as exc:
        raise AssertionError(
            f"cannot enumerate aurora-postgresql engine versions: "
            f"{exc.response.get('Error', {}).get('Code')!r}"
        ) from exc
    if not versions:
        raise AssertionError("no aurora-postgresql engine version is orderable in this region")
    return versions[0]["EngineVersion"]


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


def _scalar(resp):
    """The single scalar out of an rds-data ExecuteStatement result set."""
    records = resp.get("records") or []
    assert records and records[0], f"ExecuteStatement returned no records: {resp!r}"
    field = records[0][0]
    for key in ("longValue", "stringValue", "doubleValue", "booleanValue"):
        if key in field:
            return field[key]
    raise AssertionError(f"unexpected rds-data field shape: {field!r}")


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Data API rolled-back transactions leave no trace and committed ones persist; a stale
    transactionId is refused with TransactionNotFoundException, a malformed one with
    ValidationException."""
    rds = ctx.client("rds")
    data = ctx.client("rds-data")
    version = _serverless_v2_version(rds)

    cl_id = ctx.unique_name("sim2real-behav-clus-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    try:
        rds.create_db_cluster(
            DBClusterIdentifier=cl_id,
            Engine="aurora-postgresql",
            EngineVersion=version,
            MasterUsername=_USER,
            # Managed credentials keep the Data API's secret out of this check entirely.
            ManageMasterUserPassword=True,
            DatabaseName=_DB,
            EnableHttpEndpoint=True,
            ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 4.0},
            BackupRetentionPeriod=1,
            DeletionProtection=False,
            Tags=_MANAGED_TAGS,
            DBSubnetGroupName=subnet_group,
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("InvalidParameterCombination", "InvalidParameterValue"):
            raise AssertionError(
                "this region/engine version does not accept EnableHttpEndpoint with managed "
                f"master credentials ({code}), so the Data API cannot be exercised"
            ) from exc
        raise
    # Registered FIRST -> torn down LAST, after the member is gone.
    ctx.on_cleanup(lambda: _delete_cluster(rds, cl_id))

    member_id = ctx.unique_name("sim2real-behav-wrtr-")
    rds.create_db_instance(
        DBInstanceIdentifier=member_id,
        DBClusterIdentifier=cl_id,
        Engine="aurora-postgresql",
        DBInstanceClass="db.serverless",
        Tags=_MANAGED_TAGS,
    )
    # Registered LAST -> torn down FIRST, before the cluster.
    ctx.on_cleanup(lambda: _delete_instance(rds, member_id, wait_s=900))

    _wait_instance_available(rds, member_id)
    cluster = _poll(
        lambda: _cluster(rds, cl_id),
        lambda c: c is not None and c.get("Status") == "available",
        timeout_s=1800,
    )
    assert cluster is not None and cluster["Status"] == "available", (
        f"cluster {cl_id} did not reach 'available'; last {cluster!r}"
    )
    assert cluster.get("HttpEndpointEnabled") is True, (
        "the cluster must report HttpEndpointEnabled=True after being created with "
        f"EnableHttpEndpoint; got {cluster.get('HttpEndpointEnabled')!r} — the Data API is off"
    )
    cluster_arn = cluster["DBClusterArn"]
    secret_arn = (cluster.get("MasterUserSecret") or {}).get("SecretArn")
    assert secret_arn, (
        "ManageMasterUserPassword must publish MasterUserSecret.SecretArn; the Data API cannot "
        f"authenticate without it (MasterUserSecret={cluster.get('MasterUserSecret')!r})"
    )
    secret_status = _poll(
        lambda: ((_cluster(rds, cl_id) or {}).get("MasterUserSecret") or {}).get("SecretStatus"),
        lambda s: s == "active",
        timeout_s=900,
        interval_s=20,
    )
    assert secret_status == "active", (
        f"the managed master-user secret must become 'active'; it is {secret_status!r}"
    )

    def _exec(sql, *, txn=None):
        """One ExecuteStatement, optionally inside a transaction."""
        kwargs = {
            "resourceArn": cluster_arn,
            "secretArn": secret_arn,
            "database": _DB,
            "sql": sql,
        }
        if txn:
            kwargs["transactionId"] = txn
        return data.execute_statement(**kwargs)

    # The Data API endpoint can take a while to accept the first call after the cluster is up.
    deadline = time.monotonic() + 600
    while True:
        exc = _client_error(lambda: _exec("SELECT 1"))
        if exc is None:
            break
        code = exc.response.get("Error", {}).get("Code")
        if code in ("BadRequestException", "StatementTimeoutException", "InternalServerErrorException"):
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"the Data API never accepted a trivial statement on {cluster_arn}: "
                    f"{code} {exc.response.get('Error', {}).get('Message')!r}"
                )
            time.sleep(2)
            continue
        raise exc

    _exec(f"CREATE TABLE {_TABLE} (id INT PRIMARY KEY, val TEXT NOT NULL)")
    _exec(f"INSERT INTO {_TABLE} (id, val) VALUES (1, 'committed-baseline')")
    assert int(_scalar(_exec(f"SELECT count(*) FROM {_TABLE}"))) == 1, (
        "the Data API must persist a non-transactional insert"
    )

    # --- (1) Inside a transaction: read-your-writes.
    txn = data.begin_transaction(
        resourceArn=cluster_arn, secretArn=secret_arn, database=_DB
    )["transactionId"]
    assert txn, "BeginTransaction must return a transactionId"
    rolled_back = {"done": False}

    def _rollback_if_open():
        if not rolled_back["done"]:
            try:
                data.rollback_transaction(resourceArn=cluster_arn, secretArn=secret_arn, transactionId=txn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "DatabaseNotFoundException",
                    "NotFoundException",
                    "TransactionNotFoundException",
                ):
                    raise

    ctx.on_cleanup(_rollback_if_open)

    _exec(f"INSERT INTO {_TABLE} (id, val) VALUES (2, 'doomed-a')", txn=txn)
    _exec(f"INSERT INTO {_TABLE} (id, val) VALUES (3, 'doomed-b')", txn=txn)
    inside = int(_scalar(_exec(f"SELECT count(*) FROM {_TABLE}", txn=txn)))
    assert inside == 3, (
        "a statement inside a transaction must see that transaction's own uncommitted writes "
        f"(read-your-writes); it counts {inside} rows instead of 3"
    )

    # --- (2) Outside the transaction: isolation.
    outside = int(_scalar(_exec(f"SELECT count(*) FROM {_TABLE}")))
    assert outside == 1, (
        "a statement OUTSIDE the transaction must not see its uncommitted writes; it counts "
        f"{outside} rows instead of 1 — the emulator is applying transactional writes eagerly"
    )

    # --- (3) Rollback erases them.
    status = data.rollback_transaction(
        resourceArn=cluster_arn, secretArn=secret_arn, transactionId=txn
    )["transactionStatus"]
    rolled_back["done"] = True
    assert status, f"RollbackTransaction must report a transactionStatus; got {status!r}"
    after = int(_scalar(_exec(f"SELECT count(*) FROM {_TABLE}")))
    assert after == 1, (
        f"RollbackTransaction must discard both inserts, leaving the 1 committed baseline row; "
        f"the table holds {after} rows"
    )
    rows = _exec(f"SELECT val FROM {_TABLE} ORDER BY id").get("records") or []
    assert [r[0].get("stringValue") for r in rows] == ["committed-baseline"], (
        f"the rolled-back rows must be gone by value, not just by count; got {rows!r}"
    )

    # --- A stale transactionId must be refused, not silently reused.
    exc = _client_error(lambda: _exec(f"INSERT INTO {_TABLE} (id, val) VALUES (4, 'stale')", txn=txn))
    assert exc is not None, (
        "ExecuteStatement with an already-rolled-back transactionId was ACCEPTED; the "
        "transaction id must be invalidated by the rollback"
    )
    # RollbackTransaction deletes the transaction, so the id no longer resolves at all.
    stale_code = exc.response.get("Error", {}).get("Code")
    assert stale_code == "TransactionNotFoundException", (
        f"a rolled-back transactionId must no longer resolve, so the refusal is the modelled "
        f"TransactionNotFoundException; got {stale_code!r}: "
        f"{exc.response.get('Error', {}).get('Message')!r}"
    )
    stale_message = exc.response.get("Error", {}).get("Message")
    assert stale_message == (
        "INVALID_ARGUMENT: Transaction error: one previous call resulted in a termination of "
        "your transaction"
    ), (
        f"unexpected TransactionNotFoundException message for the rolled-back id: {stale_message!r}"
    )
    assert exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404, (
        f"TransactionNotFoundException is modelled @httpError(404); got "
        f"{exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')!r}"
    )
    # A malformed id is refused on format before any transaction lookup happens.
    malformed = _client_error(
        lambda: _exec("SELECT 1", txn="sim2real-behav-no-such-transaction-id")
    )
    assert malformed is not None, (
        "ExecuteStatement with a syntactically invalid transactionId was ACCEPTED"
    )
    malformed_code = malformed.response.get("Error", {}).get("Code")
    assert malformed_code == "ValidationException", (
        f"a malformed transactionId must be refused on format validation with "
        f"ValidationException, before the transaction lookup that produces "
        f"TransactionNotFoundException; got {malformed_code!r}: "
        f"{malformed.response.get('Error', {}).get('Message')!r}"
    )
    malformed_message = malformed.response.get("Error", {}).get("Message")
    assert malformed_message == "Invalid transaction ID", (
        f"unexpected ValidationException message for the malformed id: {malformed_message!r}"
    )
    assert malformed_code != stale_code, (
        "a malformed transactionId and a well-formed but rolled-back one must not collapse to the "
        f"same error; both returned {malformed_code!r}"
    )
    assert int(_scalar(_exec(f"SELECT count(*) FROM {_TABLE}"))) == 1, (
        "the statement on the stale transaction must not have written anything"
    )

    # --- (4) Control case: a COMMITTED transaction persists.
    txn2 = data.begin_transaction(
        resourceArn=cluster_arn, secretArn=secret_arn, database=_DB
    )["transactionId"]
    assert txn2 != txn, (
        f"each BeginTransaction must mint a distinct transactionId; got {txn2!r} twice"
    )
    _exec(f"INSERT INTO {_TABLE} (id, val) VALUES (5, 'committed-in-txn')", txn=txn2)
    data.commit_transaction(resourceArn=cluster_arn, secretArn=secret_arn, transactionId=txn2)
    rows = _exec(f"SELECT id, val FROM {_TABLE} ORDER BY id").get("records") or []
    got = [(r[0].get("longValue"), r[1].get("stringValue")) for r in rows]
    assert got == [(1, "committed-baseline"), (5, "committed-in-txn")], (
        "after the commit the table must hold exactly the baseline row and the committed "
        f"transactional row; got {got!r}"
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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=300.0, interval_s=2.0):
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
