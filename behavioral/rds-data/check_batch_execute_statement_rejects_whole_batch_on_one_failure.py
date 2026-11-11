"""batch-execute-statement-rejects-whole-batch-on-one-failure."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-execute-statement-rejects-whole-batch-on-one-failure"
GROUP = 'rejection'
SERVICES = ['rds-data']

_DB = "simparitydb"
_USER = "sim2real"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

# CreateDBCluster to the first accepted Data API statement takes roughly 500 s on AWS; these
# ceilings leave about 2.4x headroom and make up this check's declared deadline.
_MEMBER_WAIT_S = 1200
_CLUSTER_WAIT_S = 600
_SECRET_WAIT_S = 300
_DATA_API_WAIT_S = 300
_TEARDOWN_WAIT_S = 900
_CLUSTER_RETRY_S = 300
# The member wait, the cluster retry and the subnet-group wait stay 120 s inside the 1800 s cleanup
# budget, so the last teardown still fails with its own error.
_SUBNET_GROUP_WAIT_S = 1800 - _TEARDOWN_WAIT_S - _CLUSTER_RETRY_S - 120


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
    """Delete a cluster member and WAIT for it to vanish. The wait is load-bearing: a cluster
    cannot be deleted while a member remains, so the sibling cleanup registered before this one
    would fail without it."""
    try:
        rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "DBInstanceNotFound":
            raise
    left = _poll(lambda: _instance(rds, inst_id), lambda i: i is None,
                 timeout_s=_TEARDOWN_WAIT_S, interval_s=2)
    if left is not None:
        raise RuntimeError(
            f"cluster member {inst_id} still exists {_TEARDOWN_WAIT_S}s after DeleteDBInstance"
        )


def _delete_cluster(rds, cl_id):
    """Delete the cluster with no final snapshot, retrying while the member drains. Accepting
    the DeleteDBCluster call is enough: deletion then completes server-side, and the managed
    admin-user secret is deleted with the cluster."""
    deadline = time.monotonic() + _CLUSTER_RETRY_S
    while True:
        try:
            rds.delete_db_cluster(DBClusterIdentifier=cl_id, SkipFinalSnapshot=True)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "DBClusterNotFoundFault":
                return
            if code != "InvalidDBClusterStateFault" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _provision_data_api_cluster(ctx, rds, data):
    """An aurora-postgresql Serverless v2 cluster with the Data API enabled, torn down by this
    check. Returns (cluster_arn, secret_arn).

    RDS-managed credentials keep every password out of this file: the Data API authenticates
    from the managed Secrets Manager secret, whose ARN the cluster publishes, so the check never
    handles a credential. Cost safety: one db.serverless member at a 0.5 ACU floor,
    DeletionProtection=False, SkipFinalSnapshot=True. Cleanups are registered at creation in the
    order cluster -> member, so LIFO teardown deletes the MEMBER first and the cluster second.
    """
    versions = rds.describe_db_engine_versions(
        Engine="aurora-postgresql", DefaultOnly=True
    ).get("DBEngineVersions", [])
    assert versions, (
        "no aurora-postgresql engine version is orderable in "
        f"{ctx.region!r} — the Data API cannot be exercised here"
    )
    version = versions[0]["EngineVersion"]

    cl_id = ctx.unique_name("sim2real-behav-rdc-")
    subnet_group = _network_db_subnet_group(ctx, rds)
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
        Tags=_MANAGED_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    # Registered FIRST -> torn down LAST, after the member is gone.
    ctx.on_cleanup(lambda: _delete_cluster(rds, cl_id))

    member_id = ctx.unique_name("sim2real-behav-rdw-")
    rds.create_db_instance(
        DBInstanceIdentifier=member_id,
        DBClusterIdentifier=cl_id,
        Engine="aurora-postgresql",
        DBInstanceClass="db.serverless",
        Tags=_MANAGED_TAGS,
    )
    # Registered LAST -> torn down FIRST, before the cluster.
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
        f"{cluster.get('HttpEndpointEnabled')!r} — the Data API is off and nothing below runs"
    )

    secret_arn = (cluster.get("MasterUserSecret") or {}).get("SecretArn")
    assert secret_arn, (
        "ManageMasterUserPassword must publish MasterUserSecret.SecretArn; the Data API cannot "
        f"authenticate without it (MasterUserSecret={cluster.get('MasterUserSecret')!r})"
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
    # A cold Data API endpoint can refuse the first statement after 'available', so any refusal
    # is retried to the deadline and then reported verbatim (no error-code allowlist).
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
    """The ClientError fn() raised. Raises AssertionError if the call SUCCEEDED — an emulator
    accepting a statement real AWS refuses is the strongest signal here, and a falsy sentinel
    would disguise it as a mere error-code mismatch."""
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

_TABLE = "sim2real_behav_batch_atomicity"
_DUPLICATE_KEY_MESSAGE = (
    f'ERROR: duplicate key value violates unique constraint "{_TABLE}_pkey"; SQLState: 23505'
)


def _grade(data, resource_arn, secret_arn) -> None:
    """Every assertion this check makes, against an already-provisioned Data API cluster."""

    def ex(sql, **kw):
        return data.execute_statement(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB, sql=sql, **kw)

    def batch(*ids):
        return data.batch_execute_statement(
            resourceArn=resource_arn, secretArn=secret_arn, database=_DB,
            sql=f"INSERT INTO {_TABLE} (id, v) VALUES (:id, :v)",
            parameterSets=[[{"name": "id", "value": {"longValue": i}},
                            {"name": "v", "value": {"stringValue": f"row-{i}"}}] for i in ids],
        )

    def ids_present():
        rows = ex(f"SELECT id FROM {_TABLE} ORDER BY id").get("records") or []
        return [r[0]["longValue"] for r in rows]

    ex(f"CREATE TABLE {_TABLE} (id int PRIMARY KEY, v text NOT NULL)")

    # --- (1) Positive control: a clean batch applies every set and reports one updateResults
    # entry per set.
    ok = batch(1, 2)
    assert len(ok.get("updateResults") or []) == 2, (
        f"BatchExecuteStatement must return exactly one updateResults entry per parameter set; "
        f"got {ok.get('updateResults')!r}"
    )
    assert ok["updateResults"] == [{"generatedFields": []}, {"generatedFields": []}], (
        f"each entry carries an empty generatedFields list (this table has no identity column), "
        f"present rather than absent; got {ok['updateResults']!r}"
    )
    assert "numberOfRecordsUpdated" not in ok, (
        f"a batch response reports per-set updateResults, NOT the single "
        f"numberOfRecordsUpdated that ExecuteStatement returns; got keys {sorted(ok)!r}"
    )
    assert ids_present() == [1, 2], (
        f"the control batch must have written both rows; table holds {ids_present()!r}"
    )

    # --- (2) Break exactly one thing: the MIDDLE set of three violates the primary key. The
    # sets before and after it are valid on their own.
    middle = _refusal(lambda: batch(10, 1, 11))
    assert _code(middle) == "DatabaseErrorException", (
        f"a constraint violation inside a batch must surface as the modelled "
        f"DatabaseErrorException, not a generic BadRequestException; got {_code(middle)!r}: "
        f"{_message(middle)!r}"
    )
    assert middle.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 400, (
        f"DatabaseErrorException is modelled @httpError(400); got "
        f"{middle.response.get('ResponseMetadata', {}).get('HTTPStatusCode')!r}"
    )
    assert middle.response["Error"]["Message"] == _DUPLICATE_KEY_MESSAGE, (
        f"the failure must carry the ENGINE's own unique-violation message and SQLSTATE through to "
        f"the caller; expected {_DUPLICATE_KEY_MESSAGE!r}, got {_message(middle)!r}"
    )

    # --- (3) The effect is absent, in BOTH directions. Row 10 was applied before the failing
    # set and row 11 after it, and neither may survive: the batch is all-or-nothing.
    after = ids_present()
    assert after == [1, 2], (
        f"one failing parameter set must roll the WHOLE batch back: neither the set before the "
        f"failure (id 10) nor the one after it (id 11) may persist, and the pre-existing rows "
        f"must be untouched. Expected [1, 2], got {after!r}"
    )
    assert 10 not in after, (
        f"id 10 was the set BEFORE the failing one and it survived — the batch is being applied "
        f"set by set instead of atomically; table holds {after!r}"
    )
    assert 11 not in after, (
        f"id 11 was the set AFTER the failing one and it survived — the batch did not stop at "
        f"the failure either; table holds {after!r}"
    )

    # --- (4) The same all-or-nothing when the FIRST set is the bad one, so the rollback is not
    # merely "stop after the failure".
    first_bad = _refusal(lambda: batch(2, 20, 21))
    assert _code(first_bad) == "DatabaseErrorException", (
        f"a violation in the first parameter set must fail the same way; got "
        f"{_code(first_bad)!r}: {_message(first_bad)!r}"
    )
    assert first_bad.response["Error"]["Message"] == _DUPLICATE_KEY_MESSAGE, (
        f"expected {_DUPLICATE_KEY_MESSAGE!r}, got {_message(first_bad)!r}"
    )
    assert ids_present() == [1, 2], (
        f"a failure in the FIRST set must also leave nothing behind from the later ones; table "
        f"holds {ids_present()!r}"
    )

    # --- (5) Second positive control, AFTER the two failures: batching still works, so the
    # assertions above are about atomicity and not about a poisoned table or session.
    recovered = batch(30, 31)
    assert len(recovered["updateResults"]) == 2, (
        f"a batch after two failed ones must still apply cleanly; got "
        f"{recovered['updateResults']!r}"
    )
    assert ids_present() == [1, 2, 30, 31], (
        f"the recovery batch must add exactly its own two rows; table holds {ids_present()!r}"
    )

@tags("axis:rejection", "cap:c4", "concern:negative-classes", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """One failing parameter set, placed in the middle and then first, rolls back the whole
    BatchExecuteStatement (the table reads back unchanged) with the engine's exact unique-violation
    message and SQLSTATE 23505, and a clean batch afterwards writes every row."""
    rds = ctx.client("rds")
    data = ctx.client("rds-data")
    resource_arn, secret_arn = _provision_data_api_cluster(ctx, rds, data)
    _grade(data, resource_arn, secret_arn)


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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=_SUBNET_GROUP_WAIT_S,
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
