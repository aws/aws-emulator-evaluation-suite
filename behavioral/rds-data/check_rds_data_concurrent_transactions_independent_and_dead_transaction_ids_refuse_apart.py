"""rds-data-concurrent-transactions-independent-and-dead-transaction-ids-refuse-apart."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-data-concurrent-transactions-independent-and-dead-transaction-ids-refuse-apart"
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


def _envelope(resp) -> dict:
    """The response with botocore's transport metadata removed, so a whole-envelope equality
    also grades any key real AWS does not send."""
    return {k: v for k, v in resp.items() if k != "ResponseMetadata"}


def _refused(exc, expected, what) -> None:
    """Grade one refusal against the code, HTTP status and exact message real AWS answered it
    with. The three are asserted apart so a failure names which of them diverged."""
    code, status, message = expected
    assert _code(exc) == code, (
        f"{what} must be refused with {code}; got {_code(exc)!r} / HTTP {_status(exc)!r}: "
        f"{_message(exc)!r}"
    )
    assert _status(exc) == status, (
        f"{what} must be refused with HTTP {status}; got {_status(exc)!r} ({_code(exc)!r}: "
        f"{_message(exc)!r})"
    )
    assert _message(exc) == message, (
        f"{what} must carry the message {message!r}; got {_message(exc)!r}"
    )
# ===== end shared helpers =====

_TABLE = "sim2real_behav_txn_concurrency"

# Byte-exact strings real AWS returned for each graded refusal. The unique-violation text names
# the primary-key constraint postgres derives from the table name, which is why the table is a
# fixed constant rather than a per-run unique name.
_TERMINAL_MSG = (
    "INVALID_ARGUMENT: Transaction error: one previous call resulted in a termination of your "
    "transaction"
)
_ABORTED_MSG = (
    "ERROR: current transaction is aborted, commands ignored until end of transaction block; "
    "SQLState: 25P02"
)
_DUP_MSG = (
    f'ERROR: duplicate key value violates unique constraint "{_TABLE}_pkey"; SQLState: 23505'
)
_INVALID_ID_MSG = "Invalid transaction ID"

# Each graded refusal as the code, HTTP status and exact message real AWS answered it with.
_TERMINATED = ("TransactionNotFoundException", 404, _TERMINAL_MSG)
_INVALID_ID = ("ValidationException", 400, _INVALID_ID_MSG)
_ABORTED = ("DatabaseErrorException", 400, _ABORTED_MSG)
_DUPLICATE = ("DatabaseErrorException", 400, _DUP_MSG)

# Two transaction ids that are not live transactions, each graded only on the operations below.
# The first is free text. The second is a padded 98-character literal: its exact length is
# load-bearing and must not be "tidied". Both answer 400 ValidationException on every operation
# they are sent to below.
_FREE_TEXT_ID = "sim2real-behav-not-a-real-transaction-id"
_PADDED_ID = "A" * 96 + "=="

_WRITE_ENVELOPE = {"numberOfRecordsUpdated": 1, "generatedFields": []}
_COMMITTED = {"transactionStatus": "Transaction Committed"}
_ROLLED_BACK = {"transactionStatus": "Rollback complete"}

# The payload every dead-id and malformed-id refusal carries, so that each refusal is graded by
# an absence that a replay at the end proves would otherwise have landed.
_DOOMED = (99, "must-not-land")

# The ids the dead-transaction batches below carry, and the envelope a one-set batch write
# outside any transaction answers with.
_BATCH_REPLAY_IDS = (90, 91, 92, 93)
_ONE_SET_BATCH_ENVELOPE = {"updateResults": [{"generatedFields": []}]}


def _where(kw) -> str:
    return (f"in transaction {kw['transactionId']!r}" if "transactionId" in kw
            else "outside any transaction")


def _grade(data, resource_arn, secret_arn) -> None:
    """Every assertion this check makes, against an already-provisioned Data API cluster."""

    def ex(sql, **kw):
        return data.execute_statement(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB, sql=sql, **kw)

    def insert_sql() -> str:
        return f"INSERT INTO {_TABLE} (id, v) VALUES (:id, :v)"

    def params(id_, value):
        return [{"name": "id", "value": {"longValue": id_}},
                {"name": "v", "value": {"stringValue": value}}]

    def begin():
        resp = data.begin_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB)
        txn = resp.get("transactionId")
        assert isinstance(txn, str) and txn, (
            f"BeginTransaction must return a non-empty transactionId; got {txn!r}"
        )
        return txn

    def insert(id_, value, **kw):
        resp = ex(insert_sql(), parameters=params(id_, value), **kw)
        assert _envelope(resp) == _WRITE_ENVELOPE, (
            f"a single-row INSERT {_where(kw)} must answer exactly {_WRITE_ENVELOPE!r}; got "
            f"{_envelope(resp)!r}"
        )
        return resp

    def rows(**kw):
        resp = ex(f"SELECT id, v FROM {_TABLE} ORDER BY id", **kw)
        return [(r[0]["longValue"], r[1]["stringValue"])
                for r in resp.get("records") or []]

    def batch(id_, value, **kw):
        return data.batch_execute_statement(
            resourceArn=resource_arn, secretArn=secret_arn, database=_DB,
            sql=insert_sql(), parameterSets=[params(id_, value)], **kw,
        )

    ex(f"CREATE TABLE {_TABLE} (id int PRIMARY KEY, v text NOT NULL)")
    insert(1, "baseline")
    baseline = [(1, "baseline")]
    seen = rows()
    assert seen == baseline, (
        f"the committed baseline row must be readable before any transaction opens; expected "
        f"{baseline!r}, got {seen!r}"
    )

    txn_a = begin()
    txn_b = begin()
    assert txn_a != txn_b, (
        f"two BeginTransaction calls held open at once must return different transaction ids; "
        f"both were {txn_a!r}"
    )

    insert(10, "txn-a-10", transactionId=txn_a)
    insert(20, "txn-b-20", transactionId=txn_b)

    in_a = rows(transactionId=txn_a)
    expected_a = baseline + [(10, "txn-a-10")]
    assert in_a == expected_a, (
        f"a read inside transaction A must see A's own uncommitted row and no row written by the "
        f"concurrently open transaction B; expected {expected_a!r}, got {in_a!r}"
    )
    in_b = rows(transactionId=txn_b)
    expected_b = baseline + [(20, "txn-b-20")]
    assert in_b == expected_b, (
        f"a read inside transaction B must see B's own uncommitted row and no row written by the "
        f"concurrently open transaction A; expected {expected_b!r}, got {in_b!r}"
    )
    outside = rows()
    assert outside == baseline, (
        f"a read outside both transactions must see neither uncommitted row; expected "
        f"{baseline!r}, got {outside!r}"
    )

    insert(11, "txn-a-11", transactionId=txn_a)
    in_b_again = rows(transactionId=txn_b)
    assert in_b_again == expected_b, (
        f"a further uncommitted write in transaction A must stay invisible to the still-open "
        f"transaction B; expected {expected_b!r}, got {in_b_again!r}"
    )

    commit_a = data.commit_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                       transactionId=txn_a)
    assert _envelope(commit_a) == _COMMITTED, (
        f"CommitTransaction on a live transaction must answer exactly {_COMMITTED!r}; got "
        f"{_envelope(commit_a)!r}"
    )

    a_committed = baseline + [(10, "txn-a-10"), (11, "txn-a-11")]
    b_sees = sorted(a_committed + [(20, "txn-b-20")])
    in_b_after_a = rows(transactionId=txn_b)
    assert in_b_after_a == b_sees, (
        f"transaction B is still open and reads at READ COMMITTED, so after A commits B must see "
        f"every row A committed alongside its own uncommitted row; expected {b_sees!r}, got "
        f"{in_b_after_a!r}"
    )
    outside_after_a = rows()
    assert outside_after_a == a_committed, (
        f"outside both transactions only A's committed rows may be visible, not B's uncommitted "
        f"row; expected {a_committed!r}, got {outside_after_a!r}"
    )

    rollback_b = data.rollback_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                           transactionId=txn_b)
    assert _envelope(rollback_b) == _ROLLED_BACK, (
        f"RollbackTransaction on a live transaction must answer exactly {_ROLLED_BACK!r}; got "
        f"{_envelope(rollback_b)!r}"
    )
    after_rollback = rows()
    assert after_rollback == a_committed, (
        f"rolling back B must discard only B's row and leave every row A committed in place; "
        f"expected {a_committed!r}, got {after_rollback!r}"
    )

    _refused(
        _refusal(lambda: data.commit_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                                 transactionId=txn_b)),
        _TERMINATED,
        "CommitTransaction on a transaction id that was already rolled back",
    )
    _refused(
        _refusal(lambda: batch(90, "must-not-land", transactionId=txn_a)),
        _TERMINATED,
        "BatchExecuteStatement on a transaction id that was already committed",
    )
    _refused(
        _refusal(lambda: batch(91, "must-not-land", transactionId=txn_b)),
        _TERMINATED,
        "BatchExecuteStatement on a transaction id that was already rolled back",
    )
    after_dead = rows()
    assert after_dead == a_committed, (
        f"a commit and two batches refused on terminated transaction ids must write nothing; "
        f"expected {a_committed!r}, got {after_dead!r}"
    )

    txn_c = begin()
    insert(30, "txn-c-30", transactionId=txn_c)
    expected_c = sorted(a_committed + [(30, "txn-c-30")])
    in_c = rows(transactionId=txn_c)
    assert in_c == expected_c, (
        f"transaction C must read its own uncommitted row before it is aborted, which is what "
        f"makes the write path demonstrably live; expected {expected_c!r}, got {in_c!r}"
    )

    _refused(
        _refusal(lambda: ex(insert_sql(), parameters=params(1, "collides-with-baseline"),
                            transactionId=txn_c)),
        _DUPLICATE,
        "an INSERT inside transaction C that collides with the baseline primary key",
    )
    _refused(
        _refusal(lambda: batch(92, "must-not-land", transactionId=txn_c)),
        _ABORTED,
        "BatchExecuteStatement on a transaction id that is still live but aborted",
    )

    commit_c = data.commit_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                       transactionId=txn_c)
    assert _envelope(commit_c) == _COMMITTED, (
        f"CommitTransaction on an aborted transaction must answer exactly {_COMMITTED!r}, the "
        f"same body a successful commit returns; got {_envelope(commit_c)!r}"
    )
    assert commit_c.get("ResponseMetadata", {}).get("HTTPStatusCode") == 200, (
        f"CommitTransaction on an aborted transaction must answer HTTP 200; got "
        f"{commit_c.get('ResponseMetadata', {}).get('HTTPStatusCode')!r}"
    )
    after_commit_c = rows()
    assert after_commit_c == a_committed, (
        f"the accepted commit of an aborted transaction must persist nothing: neither the row C "
        f"wrote before it aborted nor anything after; expected {a_committed!r}, got "
        f"{after_commit_c!r}"
    )

    _refused(
        _refusal(lambda: batch(93, "must-not-land", transactionId=txn_c)),
        _TERMINATED,
        "BatchExecuteStatement on the aborted transaction id after its commit was accepted",
    )

    txn_d = begin()
    insert(40, "txn-d-40", transactionId=txn_d)
    commit_d = data.commit_transaction(resourceArn=resource_arn, secretArn=secret_arn,
                                       transactionId=txn_d)
    assert _envelope(commit_d) == _COMMITTED, (
        f"CommitTransaction on the control transaction D must answer exactly {_COMMITTED!r}; got "
        f"{_envelope(commit_d)!r}"
    )
    d_committed = a_committed + [(40, "txn-d-40")]
    after_d = rows()
    assert after_d == d_committed, (
        f"the control proves this table still accepts and persists an ordinary committed write, "
        f"so the absent row from the aborted transaction cannot be blamed on a dead write path; "
        f"expected {d_committed!r}, got {after_d!r}"
    )

    empty_id = ex("SELECT 1", transactionId="")
    assert _envelope(empty_id) == {"records": [[{"longValue": 1}]],
                                   "numberOfRecordsUpdated": 0}, (
        "an empty transactionId must be treated as absent and the statement run on its own, "
        "answering exactly {'records': [[{'longValue': 1}]], 'numberOfRecordsUpdated': 0}; got "
        f"{_envelope(empty_id)!r}"
    )

    doomed_id, doomed_v = _DOOMED
    for txn_id, label in ((_FREE_TEXT_ID, "free text"),
                          (_PADDED_ID, "base64-shaped but never issued")):
        _refused(
            _refusal(lambda t=txn_id: data.commit_transaction(
                resourceArn=resource_arn, secretArn=secret_arn, transactionId=t)),
            _INVALID_ID,
            f"CommitTransaction on a {label} transaction id",
        )
        _refused(
            _refusal(lambda t=txn_id: data.rollback_transaction(
                resourceArn=resource_arn, secretArn=secret_arn, transactionId=t)),
            _INVALID_ID,
            f"RollbackTransaction on a {label} transaction id",
        )
    _refused(
        _refusal(lambda: batch(doomed_id, doomed_v, transactionId=_FREE_TEXT_ID)),
        _INVALID_ID,
        "BatchExecuteStatement on a free text transaction id",
    )
    _refused(
        _refusal(lambda: ex(insert_sql(), parameters=params(doomed_id, doomed_v),
                            transactionId=_PADDED_ID)),
        _INVALID_ID,
        "ExecuteStatement on a base64-shaped but never issued transaction id",
    )

    after_invalid = rows()
    assert after_invalid == d_committed, (
        f"every refusal on a malformed or never-issued transaction id carried a write payload "
        f"that must not have landed; expected {d_committed!r}, got {after_invalid!r}"
    )

    insert(doomed_id, doomed_v)
    replayed = rows()
    assert replayed == d_committed + [_DOOMED], (
        f"replaying the refused payload outside any transaction must land it, proving the "
        f"refusals above suppressed a write that would otherwise have been applied; expected "
        f"{d_committed + [_DOOMED]!r}, got {replayed!r}"
    )

    # Same-operation positive control: each payload refused through BatchExecuteStatement on a
    # dead or malformed id lands when that exact batch is replayed with no transaction, so its
    # absence above was the transaction's refusal and not a batch that could never write.
    for id_ in _BATCH_REPLAY_IDS:
        landed = batch(id_, "must-not-land")
        assert _envelope(landed) == _ONE_SET_BATCH_ENVELOPE, (
            f"a one-set batch INSERT outside any transaction must answer exactly "
            f"{_ONE_SET_BATCH_ENVELOPE!r}; got {_envelope(landed)!r}"
        )
    removed = data.batch_execute_statement(
        resourceArn=resource_arn, secretArn=secret_arn, database=_DB,
        sql=f"DELETE FROM {_TABLE} WHERE id = :id",
        parameterSets=[[{"name": "id", "value": {"longValue": doomed_id}}]],
    )
    assert _envelope(removed) == _ONE_SET_BATCH_ENVELOPE, (
        f"a one-set batch DELETE must answer exactly {_ONE_SET_BATCH_ENVELOPE!r}; got "
        f"{_envelope(removed)!r}"
    )
    batch_rows = [(id_, "must-not-land") for id_ in _BATCH_REPLAY_IDS]
    cleared = rows()
    assert cleared == d_committed + batch_rows, (
        f"the replayed batches must have landed and the batch DELETE removed id {doomed_id}, so "
        f"the doomed payload can be replayed through the batch operation too; expected "
        f"{d_committed + batch_rows!r}, got {cleared!r}"
    )
    doomed_batch = batch(doomed_id, doomed_v)
    assert _envelope(doomed_batch) == _ONE_SET_BATCH_ENVELOPE, (
        f"the doomed payload replayed as a one-set batch must answer exactly "
        f"{_ONE_SET_BATCH_ENVELOPE!r}; got {_envelope(doomed_batch)!r}"
    )
    batch_replayed = rows()
    assert batch_replayed == d_committed + batch_rows + [_DOOMED], (
        f"replaying every batch payload refused above, with no transaction, must land each of "
        f"them; expected {d_committed + batch_rows + [_DOOMED]!r}, got {batch_replayed!r}"
    )


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two transaction ids held open at once are independent sessions reading at READ COMMITTED.
    A commit on an aborted transaction is accepted with the ordinary committed body and persists
    nothing, while terminated, aborted and unparseable transaction ids refuse in three classes.

    Reference: https://docs.aws.amazon.com/rdsdataservice/latest/APIReference/API_BeginTransaction.html
    Reference: https://docs.aws.amazon.com/rdsdataservice/latest/APIReference/API_CommitTransaction.html
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
