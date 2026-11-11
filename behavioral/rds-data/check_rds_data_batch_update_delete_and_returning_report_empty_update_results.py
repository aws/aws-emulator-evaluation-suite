"""rds-data-batch-update-delete-and-returning-report-empty-update-results."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-data-batch-update-delete-and-returning-report-empty-update-results"
GROUP = "data-plane"
SERVICES = ["rds-data"]

_DB = "simparitydb"
_USER = "sim2real"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

# CreateDBCluster to the first accepted Data API statement measures roughly 500 s on AWS; the
# member wait below is about 2.4x that measurement, and together with the other ceilings makes
# up this check's declared deadline.
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


def _only_cell(resp, arm):
    """The single cell of a one-row one-column result."""
    [[cell]] = resp["records"]
    return cell[arm]
# ===== end shared helpers =====

_TABLE = "sim2real_behav_batch_shapes"
_ONCE_TABLE = "sim2real_behav_batch_once"
_DDL_WITH_SETS = "sim2real_behav_batch_ddl_a"
_DDL_WITHOUT_SETS = "sim2real_behav_batch_ddl_b"

# Byte-exact messages real AWS returned for each graded refusal. The not-null text names the
# column and the relation, which is why both are fixed constants rather than per-run names.
_MISSING_V_MSG = "Cannot find parameter: v"
_MISSING_ID_MSG = "Cannot find parameter: id"
_ARRAY_MSG = "Array parameters are not supported."
_NOT_NULL_MSG = (
    f'ERROR: null value in column "v" of relation "{_TABLE}" violates not-null constraint; '
    f"SQLState: 23502"
)

_EMPTY = {"generatedFields": []}
_BASELINE = [(1, "a"), (2, "b"), (3, "c"), (4, "d")]

# Each graded refusal as the code, HTTP status and exact message real AWS answered it with.
_MISSING_V = ("ValidationException", 400, _MISSING_V_MSG)
_MISSING_ID = ("ValidationException", 400, _MISSING_ID_MSG)
_ARRAY_PARAM = ("ValidationException", 400, _ARRAY_MSG)
_NOT_NULL = ("DatabaseErrorException", 400, _NOT_NULL_MSG)


def _grade(data, resource_arn, secret_arn) -> None:
    """Every assertion this check makes, against an already-provisioned Data API cluster."""

    def ex(sql, **kw):
        return data.execute_statement(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB, sql=sql, **kw)

    def batch(sql, sets=None, **kw):
        call = dict(resourceArn=resource_arn, secretArn=secret_arn, database=_DB, sql=sql)
        if sets is not None:
            call["parameterSets"] = sets
        call.update(kw)
        return data.batch_execute_statement(**call)

    def pset(id_=None, v=None, **extra):
        out = []
        if id_ is not None:
            out.append({"name": "id", "value": {"longValue": id_}})
        if v is not None:
            out.append({"name": "v", "value": v})
        out.extend({"name": name, "value": value} for name, value in extra.items())
        return out

    def text(value):
        return {"stringValue": value}

    def rows(table=_TABLE):
        resp = ex(f"SELECT id, v FROM {table} ORDER BY id, v")
        return [(r[0]["longValue"], r[1]["stringValue"])
                for r in resp.get("records") or []]

    def count(table, where):
        resp = ex(f"SELECT count(*) FROM {table} WHERE {where}")
        return _only_cell(resp, "longValue")

    def graded_batch(sql, sets, *, entries, what, **kw):
        resp = batch(sql, sets, **kw)
        assert _envelope(resp) == {"updateResults": [_EMPTY] * entries}, (
            f"{what} must answer exactly {entries} updateResults entries, every one of them "
            f"{_EMPTY!r}, and no numberOfRecordsUpdated, records or formattedRecords key at all; "
            f"got {_envelope(resp)!r}"
        )
        return resp

    ex(f"CREATE TABLE {_TABLE} (id int PRIMARY KEY, v text NOT NULL)")
    ex(f"INSERT INTO {_TABLE} (id, v) VALUES "
       + ", ".join(f"({i}, '{v}')" for i, v in _BASELINE))
    seeded = rows()
    assert seeded == _BASELINE, (
        f"the baseline rows must be readable before the first batch runs; expected "
        f"{_BASELINE!r}, got {seeded!r}"
    )

    graded_batch(
        f"UPDATE {_TABLE} SET v = :v WHERE id = :id",
        [pset(1, text("A")), pset(2, text("B")), pset(99, text("Z"))],
        entries=3,
        what="a batched UPDATE of three parameter sets, one of which matches no row",
    )
    state = [(1, "A"), (2, "B"), (3, "c"), (4, "d")]
    after_update = rows()
    assert after_update == state, (
        f"the two matching parameter sets must have been applied and the non-matching one must "
        f"have changed nothing, even though all three entries report the same empty body; "
        f"expected {state!r}, got {after_update!r}"
    )

    graded_batch(
        f"UPDATE {_TABLE} SET v = :v WHERE id > :id",
        [pset(2, text("G2"))],
        entries=1,
        what="a batched UPDATE of one parameter set that matches two rows",
    )
    state = [(1, "A"), (2, "B"), (3, "G2"), (4, "G2")]
    after_many = rows()
    assert after_many == state, (
        f"one parameter set matching two rows must update both while still reporting a single "
        f"entry, so the entry count tracks parameter sets and not rows; expected {state!r}, got "
        f"{after_many!r}"
    )

    graded_batch(
        f"DELETE FROM {_TABLE} WHERE id = :id",
        [pset(4), pset(99)],
        entries=2,
        what="a batched DELETE of two parameter sets, one of which matches no row",
    )
    state = [(1, "A"), (2, "B"), (3, "G2")]
    after_delete = rows()
    assert after_delete == state, (
        f"the matching DELETE set must have removed its row and the non-matching one must have "
        f"removed nothing; expected {state!r}, got {after_delete!r}"
    )

    graded_batch(
        f"DELETE FROM {_TABLE} WHERE id < :id",
        [pset(3)],
        entries=1,
        what="a batched DELETE of one parameter set that matches two rows",
    )
    state = [(3, "G2")]
    after_delete_many = rows()
    assert after_delete_many == state, (
        f"one DELETE set matching two rows must remove both and still report a single entry; "
        f"expected {state!r}, got {after_delete_many!r}"
    )

    graded_batch(
        f"INSERT INTO {_TABLE} (id, v) VALUES (:id, :v) RETURNING id",
        [pset(10, text("r10")), pset(11, text("r11"))],
        entries=2,
        what="a batched INSERT ... RETURNING id of two parameter sets",
    )
    state = state + [(10, "r10"), (11, "r11")]
    after_returning = rows()
    assert after_returning == state, (
        f"the rows a batched RETURNING wrote must be present even though the returned rows are "
        f"reported nowhere in the response; expected {state!r}, got {after_returning!r}"
    )

    graded_batch(
        f"UPDATE {_TABLE} SET v = :v WHERE id >= :id RETURNING *",
        [pset(10, text("R"))],
        entries=1,
        what="a batched UPDATE ... RETURNING * of one parameter set matching two rows",
    )
    state = [(3, "G2"), (10, "R"), (11, "R")]
    after_update_returning = rows()
    assert after_update_returning == state, (
        f"a batched UPDATE ... RETURNING * must apply to both matching rows and discard the "
        f"returned rows; expected {state!r}, got {after_update_returning!r}"
    )

    graded_batch(
        f"DELETE FROM {_TABLE} WHERE id = :id RETURNING id, v",
        [pset(11)],
        entries=1,
        what="a batched DELETE ... RETURNING of one parameter set",
    )
    state = [(3, "G2"), (10, "R")]
    after_delete_returning = rows()
    assert after_delete_returning == state, (
        f"a batched DELETE ... RETURNING must remove its row and discard the returned row; "
        f"expected {state!r}, got {after_delete_returning!r}"
    )

    graded_batch(
        f"SELECT v FROM {_TABLE} WHERE id = :id",
        [pset(3), pset(10)],
        entries=2,
        what="a batched SELECT of two parameter sets, both matching a row",
    )

    direct = ex(f"INSERT INTO {_TABLE} (id, v) VALUES (20, 'e20') RETURNING id")
    assert _envelope(direct) == {"records": [[{"longValue": 20}]],
                                 "numberOfRecordsUpdated": 0}, (
        "ExecuteStatement must report the RETURNING row that the batch form discards, answering "
        "exactly {'records': [[{'longValue': 20}]], 'numberOfRecordsUpdated': 0} with no "
        "generatedFields key; got "
        f"{_envelope(direct)!r}"
    )
    state = state + [(20, "e20")]

    graded_batch(
        f"INSERT INTO {_TABLE} (id, v) VALUES (:id, :v)",
        [pset(21, text("surplus"), nope=text("ignored"))],
        entries=1,
        what="a batched INSERT whose parameter set carries a parameter the statement never names",
    )
    state = state + [(21, "surplus")]
    after_surplus = rows()
    assert after_surplus == state, (
        f"the unnamed surplus parameter must be ignored rather than refused or substituted, and "
        f"the row must land with the values the statement does name; expected {state!r}, got "
        f"{after_surplus!r}"
    )

    ex(f"CREATE TABLE {_ONCE_TABLE} (id int, v text)")
    once_legs = [
        (30, "p-omitted", None, "with parameterSets omitted entirely"),
        (31, "p-empty", [], "with parameterSets set to an empty list"),
        (32, "p-empty-set", [[]], "with parameterSets set to one empty parameter set"),
    ]
    for id_, value, sets, label in once_legs:
        graded_batch(
            f"INSERT INTO {_ONCE_TABLE} (id, v) VALUES ({id_}, '{value}')",
            sets,
            entries=1,
            what=f"a batched INSERT of a statement that binds nothing, {label}",
        )
        landed = count(_ONCE_TABLE, f"id = {id_}")
        assert landed == 1, (
            f"a batched statement {label} must run exactly once, so the table that has no unique "
            f"constraint to hide a repeat must hold one row with id {id_}; it holds {landed}"
        )

    for table, sets, label in ((_DDL_WITH_SETS, [[]], "with one empty parameter set"),
                               (_DDL_WITHOUT_SETS, None, "with parameterSets omitted")):
        graded_batch(
            f"CREATE TABLE {table} (id int)",
            sets,
            entries=1,
            what=f"a batched CREATE TABLE {label}",
        )
        # A table that was never created refuses both of these, so the INSERT and the count are
        # what grade that the batched DDL ran and left a usable table behind.
        ex(f"INSERT INTO {table} (id) VALUES (7)")
        created_rows = count(table, "id = 7")
        assert created_rows == 1, (
            f"the table a batched CREATE TABLE {label} created must hold the one row written "
            f"into it afterwards; it holds {created_rows!r}"
        )

    snapshot = rows()
    assert snapshot == state, (
        f"the accepted batches above must have left exactly the rows accounted for before the "
        f"refusals are graded; expected {state!r}, got {snapshot!r}"
    )

    insert_sql = f"INSERT INTO {_TABLE} (id, v) VALUES (:id, :v)"
    validation_legs = [
        ([pset(40, text("ok")), pset(41)], _MISSING_V,
         "a batched INSERT one of whose parameter sets omits a parameter the statement names"),
        ([pset(40, text("ok")), []], _MISSING_ID,
         "a batched INSERT one of whose parameter sets is empty"),
        ([pset(40, text("ok")),
          pset(41, {"arrayValue": {"stringValues": ["x", "y"]}})], _ARRAY_PARAM,
         "a batched INSERT one of whose parameters is an array"),
    ]
    for sets, expected, what in validation_legs:
        _refused(_refusal(lambda s=sets: batch(insert_sql, s)), expected, what)
        unchanged = rows()
        assert unchanged == snapshot, (
            f"{what} must be refused as a whole, so neither the valid set nor the invalid one may "
            f"be applied; expected {snapshot!r}, got {unchanged!r}"
        )

    _refused(
        _refusal(lambda: batch(insert_sql,
                               [pset(40, text("ok")), pset(41, {"isNull": True})])),
        _NOT_NULL,
        "a batched INSERT one of whose parameter sets violates a not-null constraint",
    )
    unchanged = rows()
    assert unchanged == snapshot, (
        f"a batch the engine rejects must be atomic too, leaving the valid set in the same batch "
        f"unapplied; expected {snapshot!r}, got {unchanged!r}"
    )

    graded_batch(
        insert_sql,
        [pset(40, text("ok")), pset(41, text("ok"))],
        entries=2,
        what="the refused batch replayed with every parameter set valid",
    )
    replayed = rows()
    assert replayed == sorted(snapshot + [(40, "ok"), (41, "ok")]), (
        f"replaying the refused batch must land both rows, proving the refusals above held back "
        f"writes the engine would otherwise have applied; expected "
        f"{sorted(snapshot + [(40, 'ok'), (41, 'ok')])!r}, got {replayed!r}"
    )


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchExecuteStatement reports one empty generatedFields entry per parameter set for
    UPDATE, DELETE, SELECT and RETURNING statements alike, with no row counts and no returned
    rows. A parameter set the Data API cannot bind and one the engine rejects refuse apart.

    Reference: https://docs.aws.amazon.com/rdsdataservice/latest/APIReference/API_BatchExecuteStatement.html
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
