"""execute-statement-failure-aborts-transaction-and-rollback-discards-writes."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-failure-aborts-transaction-and-rollback-discards-writes"
GROUP = "state"
SERVICES = ["rds-data"]

_DB = "simparitydb"
_USER = "sim2real"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

# CreateDBCluster to the first accepted Data API statement takes around 414 s on AWS; the member
# wait below is about 2.9x that measurement, and together with the other ceilings makes up this
# check's declared deadline.
_MEMBER_WAIT_S = 1200
_CLUSTER_WAIT_S = 600
_SECRET_WAIT_S = 300
_DATA_API_WAIT_S = 300
_TEARDOWN_WAIT_S = 900


# ===== shared helpers =====


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
# ===== end shared helpers =====


def _refusal(fn):
    """The ClientError fn() raised. Raises AssertionError if the call SUCCEEDED — a target
    accepting a call real AWS refuses is the strongest signal here, and a falsy sentinel would
    disguise it as a mere error-code mismatch."""
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


def _status(exc):
    return exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")


_TABLE = "sim2real_behav_txn_abort"

# Byte-exact messages real AWS returned for each graded refusal. The unique-violation text names
# the primary-key constraint postgres derives from the table name, which is why the table is a
# fixed constant rather than a per-run unique name.
_DUP_MSG = (
    f'ERROR: duplicate key value violates unique constraint "{_TABLE}_pkey"; SQLState: 23505'
)
_ABORTED_MSG = (
    "ERROR: current transaction is aborted, commands ignored until end of transaction block; "
    "SQLState: 25P02"
)
_SYNTAX_SQL = "SELCT nope FROM nowhere"
_SYNTAX_MSG = 'ERROR: syntax error at or near "SELCT"; Position: 1; SQLState: 42601'


def _grade(data, resource_arn, secret_arn) -> None:
    """Every assertion this check makes, against an already-provisioned Data API cluster."""

    def ex(sql, **kw):
        return data.execute_statement(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB, sql=sql, **kw)

    def insert(row_id, value, **kw):
        return ex(f"INSERT INTO {_TABLE} (id, v) VALUES ({row_id}, '{value}')", **kw)

    def ids_present(**kw):
        resp = ex(f"SELECT id FROM {_TABLE} ORDER BY id", **kw)
        records = resp.get("records")
        records = [] if records is None else records
        assert isinstance(records, (list, tuple)), (
            f"ExecuteStatement must return records as a list of rows; got {records!r}"
        )
        ids = []
        for row in records:
            cell = row[0] if isinstance(row, (list, tuple)) and row else None
            assert isinstance(cell, dict) and "longValue" in cell, (
                f"each row must carry its id as a longValue cell; got row {row!r} of {records!r}"
            )
            ids.append(cell["longValue"])
        return ids

    def begin():
        resp = data.begin_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB)
        txn_id = resp.get("transactionId")
        assert isinstance(txn_id, str) and txn_id, (
            f"BeginTransaction must return a non-empty transactionId to bind statements to; got "
            f"{ {k: v for k, v in resp.items() if k != 'ResponseMetadata'} !r}"
        )
        return txn_id

    def assert_db_error(exc, expected_msg, what):
        code, status, message = "DatabaseErrorException", 400, expected_msg
        assert _code(exc) == code, (
            f"{what} must surface as the modelled DatabaseErrorException, not a generic "
            f"BadRequestException or a transaction-lifecycle error; got {_code(exc)!r}: "
            f"{_message(exc)!r}"
        )
        assert _status(exc) == status, (
            f"DatabaseErrorException is modelled @httpError(400); {what} returned HTTP "
            f"{_status(exc)!r}"
        )
        assert _message(exc) == message, (
            f"{what} must carry the ENGINE's own text and SQLSTATE through to the caller "
            f"verbatim — that is the only way a client can classify it. Expected "
            f"{message!r}, got {_message(exc)!r}"
        )

    ex(f"CREATE TABLE {_TABLE} (id int PRIMARY KEY, v text NOT NULL)")

    # --- (0) Precondition: a row written with no transaction at all, so every later "the
    # transaction's writes are gone" assertion is read against a table that is demonstrably
    # readable and non-empty rather than against a table nothing can write to.
    insert(1, "baseline")
    baseline = ids_present()
    assert baseline == [1], (
        f"precondition: the baseline row must be present and alone before the first "
        f"transaction opens; table holds {baseline!r}"
    )

    # --- (1) A transaction that writes successfully, then fails on a constraint violation.
    txn = begin()
    first = insert(10, "txn-write", transactionId=txn)
    assert first.get("numberOfRecordsUpdated") == 1, (
        f"the first statement in the transaction must report one row updated, otherwise the "
        f"rollback below is asserted against a write that never happened; got "
        f"{ {k: v for k, v in first.items() if k != 'ResponseMetadata'} !r}"
    )
    # Positive control inside the still-open transaction: the write IS there before anything
    # fails. Without it, a target whose transactionId is a no-op would score identically on the
    # post-rollback absence below.
    inside = ids_present(transactionId=txn)
    assert inside == [1, 10], (
        f"the transaction's own write must be visible to a read inside that same transaction "
        f"before the failure; the transaction sees {inside!r}"
    )

    dup = _refusal(lambda: insert(10, "duplicate", transactionId=txn))
    assert_db_error(dup, _DUP_MSG, "a primary-key violation inside an open transaction")

    # --- (2) The failure ABORTS the transaction: every later statement on that transactionId is
    # refused, including a read, and it is refused as a DATABASE error naming the aborted
    # transaction rather than as TransactionNotFound.
    poisoned_write = _refusal(lambda: insert(11, "after-failure", transactionId=txn))
    assert_db_error(
        poisoned_write, _ABORTED_MSG,
        "a fresh, individually valid insert on the transaction that already failed",
    )
    poisoned_read = _refusal(lambda: ex("SELECT 1", transactionId=txn))
    assert_db_error(
        poisoned_read, _ABORTED_MSG,
        "a trivial read on the transaction that already failed",
    )

    # --- (3) RollbackTransaction is still accepted on that aborted transaction and reports the
    # same status a rollback of a healthy transaction reports.
    rolled = data.rollback_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                       transactionId=txn)
    assert rolled.get("transactionStatus") == "Rollback complete", (
        f"rolling back an aborted transaction must report 'Rollback complete'; got "
        f"{rolled.get('transactionStatus')!r}"
    )

    after = ids_present()
    assert after == [1], (
        f"the rollback must discard the transaction's earlier SUCCESSFUL write (id 10) and "
        f"leave nothing the failed statements attempted (id 11), while the non-transactional "
        f"baseline row survives. Expected [1], got {after!r}"
    )

    # --- (4) Positive control for the absence above: replay the EXACT insert the aborted
    # transaction refused, now outside any transaction. It is accepted and lands, which proves
    # the 25P02 refusals were the transaction's state and not a statement that cannot ever
    # succeed, and that "id 11 is absent" above was a real discard rather than a write path
    # that never works.
    insert(11, "after-failure")
    replayed = ids_present()
    assert replayed == [1, 11], (
        f"the replayed insert must land outside a transaction, proving the refusal above was "
        f"about the aborted transaction; table holds {replayed!r}"
    )

    # --- (5) A second, unrelated failure class: a malformed statement. It aborts the
    # transaction the same way, so the abort is a property of failing inside a transaction and
    # not of constraint violations specifically. Distinct ids (30, 31) so this leg cannot be
    # satisfied by leftovers from the first.
    txn2 = begin()
    second = insert(30, "txn2-write", transactionId=txn2)
    assert second.get("numberOfRecordsUpdated") == 1, (
        f"this leg's pre-failure write must report one row updated, otherwise its own "
        f"post-rollback absence below is asserted against a write that never happened; got "
        f"{ {k: v for k, v in second.items() if k != 'ResponseMetadata'} !r}"
    )
    inside2 = ids_present(transactionId=txn2)
    assert inside2 == [1, 11, 30], (
        f"this leg's own write must be visible inside its still-open transaction before the "
        f"malformed statement; the transaction sees {inside2!r}"
    )
    malformed = _refusal(lambda: ex(_SYNTAX_SQL, transactionId=txn2))
    assert_db_error(malformed, _SYNTAX_MSG,
                    "a malformed statement inside an open transaction")
    poisoned2 = _refusal(lambda: insert(31, "after-syntax-error", transactionId=txn2))
    assert_db_error(
        poisoned2, _ABORTED_MSG,
        "a valid insert on the transaction a malformed statement already failed",
    )
    rolled2 = data.rollback_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                        transactionId=txn2)
    assert rolled2.get("transactionStatus") == "Rollback complete", (
        f"rolling back a transaction aborted by a malformed statement must report "
        f"'Rollback complete'; got {rolled2.get('transactionStatus')!r}"
    )
    after2 = ids_present()
    assert after2 == [1, 11], (
        f"the second rollback must discard id 30 and leave no trace of id 31, without "
        f"disturbing the rows already there. Expected [1, 11], got {after2!r}"
    )
    # This leg's own positive control, matching the first: the insert the aborted transaction
    # refused lands once it is not bound to that transaction, so id 31's absence above is a
    # discard and not a statement that could never have succeeded.
    insert(31, "after-syntax-error")
    replayed2 = ids_present()
    assert replayed2 == [1, 11, 31], (
        f"the replayed insert must land outside a transaction, proving this leg's refusal was "
        f"about the aborted transaction; table holds {replayed2!r}"
    )

    # --- (6) Closing positive control: after two aborted transactions, a clean transaction
    # still commits and its write persists — so none of the absences above can be explained by
    # transactions, or this cluster, having stopped working.
    txn3 = begin()
    insert(50, "clean", transactionId=txn3)
    committed = data.commit_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                        transactionId=txn3)
    assert committed.get("transactionStatus") == "Transaction Committed", (
        f"committing a clean transaction must report 'Transaction Committed'; got "
        f"{committed.get('transactionStatus')!r}"
    )
    final = ids_present()
    assert final == [1, 11, 31, 50], (
        f"the committed write must persist, proving transactions still work after the aborted "
        f"ones; table holds {final!r}"
    )


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c4", "concern:negative-classes",
      "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A statement that fails inside an open Data API transaction aborts it: every later
    ExecuteStatement on that transactionId, write or read, is refused 400 DatabaseErrorException
    with SQLSTATE 25P02, and RollbackTransaction still succeeds and discards the earlier writes.

    Reference: https://docs.aws.amazon.com/rdsdataservice/latest/APIReference/API_ExecuteStatement.html
    Reference: https://docs.aws.amazon.com/rdsdataservice/latest/APIReference/API_RollbackTransaction.html
    """
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
