"""rds-data-type-hint-is-required-for-engine-typed-parameters."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-data-type-hint-is-required-for-engine-typed-parameters"
GROUP = "representation"
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

_TABLE = "sim2real_behav_type_hints"

_UUID = "123e4567-e89b-12d3-a456-426614174000"

# Written with the hint, read back through the Field union. The jsonb value is sent with its keys
# in the opposite order to the one it comes back in, and the time is sent with one fractional
# digit and comes back with three, so those two round trips observe the engine's own
# normalisation. The timestamptz row carries the fraction-free value real AWS was observed with,
# so that leg establishes only that the TIMESTAMP hint is accepted on a timestamptz column and
# round-trips unchanged; it says nothing about how a fraction would be rendered there.
_HINTED = [
    ("j", "JSON", '{"b":1,"a":[2,3]}', '{"a":[2,3],"b":1}'),
    ("u", "UUID", _UUID, _UUID),
    ("ts", "TIMESTAMP", "2026-10-22 18:30:00.123456", "2026-10-22 18:30:00.123456"),
    ("tstz", "TIMESTAMP", "2026-10-22 18:30:00", "2026-10-22 18:30:00"),
    ("d", "DATE", "2026-10-22", "2026-10-22"),
    ("tm", "TIME", "18:30:00.5", "18:30:00.500"),
    ("n", "DECIMAL", "123.4567", "123.4567"),
]

# The same string without its hint: the engine refuses it, naming the column's own type and
# `text` as what it was handed. Every leg sends the same statement shape
# "INSERT INTO <table> (id, <col>) VALUES (2, :p)", so the position is fixed by the column name's
# own length, not by its type.
_UNHINTED = [
    ("j", "jsonb", 58),
    ("u", "uuid", 58),
    ("ts", "timestamp without time zone", 59),
    ("tm", "time without time zone", 59),
    ("d", "date", 58),
    ("n", "numeric", 58),
]

# Hint present, value unparseable: the Data API refuses before the engine sees anything, with no
# `ERROR:` prefix and no SQLState. Only the two values real AWS was measured with are graded.
_UNPARSEABLE = [
    ("u", "UUID", "nope-not-a-uuid", 'Cannot parse UUID parameter: "nope-not-a-uuid"'),
    ("j", "JSON", "{bad json}",
     "invalid input syntax for type json: key must be a string at line 1 column 2"),
]

_BATCH_UUID_MSG = 'Cannot parse UUID parameter: "not-a-uuid"'

# Every refusal in this check comes back under one code and status; what distinguishes the two
# families is the message, and only the engine's carries a SQLState.
_ENGINE_CODE = "DatabaseErrorException"
_ENGINE_STATUS = 400
_BATCH_UUID = (_ENGINE_CODE, _ENGINE_STATUS, _BATCH_UUID_MSG)


def _mismatch_msg(col, col_type, expr_type, position) -> str:
    """The engine's exact 42804 text for a parameter it could not assign to a column; `position`
    is the character offset of the mismatched value in the statement text actually sent, fixed by
    the length of the column name since every statement here has the same fixed shape."""
    return (
        f'ERROR: column "{col}" is of type {col_type} but expression is of type {expr_type}; '
        f"Hint: You will need to rewrite or cast the expression.; Position: {position}; "
        f"SQLState: 42804"
    )


def _engine_mismatch(exc, *, col, col_type, expr_type, position, what) -> None:
    """Grade a refusal the engine raised for a parameter it could not assign to the column,
    against the exact message real AWS answered."""
    _refused(
        exc, (_ENGINE_CODE, _ENGINE_STATUS, _mismatch_msg(col, col_type, expr_type, position)),
        what,
    )


def _grade(data, resource_arn, secret_arn) -> None:
    """Every assertion this check makes, against an already-provisioned Data API cluster."""

    def ex(sql, **kw):
        return data.execute_statement(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB, sql=sql, **kw)

    def param(name, value, hint=None):
        out = {"name": name, "value": value}
        if hint is not None:
            out["typeHint"] = hint
        return out

    def ids():
        resp = ex(f"SELECT id FROM {_TABLE} ORDER BY id")
        return [r[0]["longValue"] for r in resp.get("records") or []]

    def read(columns, id_, **kw):
        return ex(f"SELECT {columns} FROM {_TABLE} WHERE id = {id_}", **kw)

    ex(f"CREATE TABLE {_TABLE} (id int PRIMARY KEY, j jsonb, u uuid, ts timestamp, "
       f"tstz timestamptz, d date, tm time, n numeric(12,4), b bytea, "
       f"flag boolean, txt text, i int)")

    columns = ", ".join(col for col, _, _, _ in _HINTED)
    placeholders = ", ".join(f":{col}" for col, _, _, _ in _HINTED)
    hinted = ex(f"INSERT INTO {_TABLE} (id, {columns}) VALUES (1, {placeholders})",
                parameters=[param(col, {"stringValue": sent}, hint)
                            for col, hint, sent, _ in _HINTED])
    assert _envelope(hinted) == {"numberOfRecordsUpdated": 1, "generatedFields": []}, (
        "the hinted write must be accepted as an ordinary single-row INSERT, answering exactly "
        "{'numberOfRecordsUpdated': 1, 'generatedFields': []}; got "
        f"{_envelope(hinted)!r}"
    )
    round_trip = read(columns, 1)
    expected = [[{"stringValue": back} for _, _, _, back in _HINTED]]
    assert _envelope(round_trip) == {"records": expected, "numberOfRecordsUpdated": 0}, (
        f"each hinted parameter must have reached its column as that column's own type and come "
        f"back as {expected!r}; got {_envelope(round_trip)!r}"
    )

    for col, col_type, position in _UNHINTED:
        sent = next(s for c, _, s, _ in _HINTED if c == col)
        _engine_mismatch(
            _refusal(lambda c=col, s=sent: ex(
                f"INSERT INTO {_TABLE} (id, {c}) VALUES (2, :p)",
                parameters=[param("p", {"stringValue": s})])),
            col=col, col_type=col_type, expr_type="text", position=position,
            what=f"the same string written into the {col_type} column {col!r} with no typeHint",
        )

    for col, hint, sent, message in _UNPARSEABLE:
        _refused(
            _refusal(lambda c=col, h=hint, s=sent: ex(
                f"INSERT INTO {_TABLE} (id, {c}) VALUES (2, :p)",
                parameters=[param("p", {"stringValue": s}, h)])),
            (_ENGINE_CODE, _ENGINE_STATUS, message),
            f"a {hint} hint on a value that cannot be parsed as one",
        )

    _engine_mismatch(
        _refusal(lambda: ex(f"INSERT INTO {_TABLE} (id, i) VALUES (2, :p)",
                            parameters=[param("p", {"stringValue": '{"a":1}'}, "JSON")])),
        col="i", col_type="integer", expr_type="jsonb", position=58,
        what="a JSON hint carried into an integer column",
    )
    _engine_mismatch(
        _refusal(lambda: ex(f"INSERT INTO {_TABLE} (id, u) VALUES (2, :p)",
                            parameters=[param("p", {"longValue": 7}, "UUID")])),
        col="u", col_type="uuid", expr_type="bigint", position=58,
        what="a UUID hint carried on a longValue",
    )
    _engine_mismatch(
        _refusal(lambda: ex(f"INSERT INTO {_TABLE} (id, i) VALUES (2, :p)",
                            parameters=[param("p", {"booleanValue": True})])),
        col="i", col_type="integer", expr_type="boolean", position=58,
        what="a booleanValue written into an integer column",
    )

    after_refusals = ids()
    assert after_refusals == [1], (
        f"no unhinted, unparseable or mismatched write may have landed, so row 2 must be absent; "
        f"the table holds ids {after_refusals!r}"
    )

    control = next((col, hint, sent) for col, hint, sent, _ in _HINTED if col == "j")
    ex(f"INSERT INTO {_TABLE} (id, {control[0]}) VALUES (2, :p)",
       parameters=[param("p", {"stringValue": control[2]}, control[1])])
    after_control = ids()
    assert after_control == [1, 2], (
        f"the control replays the jsonb leg with its hint restored and proves that statement "
        f"shape is otherwise writable, so its earlier refusal is attributable to the missing "
        f"hint; expected ids [1, 2], got {after_control!r}"
    )

    batch_cols = [("u", "UUID", _UUID), ("j", "JSON", '{"z":1}'), ("d", "DATE", "2026-01-02")]
    batch_names = ", ".join(col for col, _, _ in batch_cols)
    batch_binds = ", ".join(f":{col}" for col, _, _ in batch_cols)
    batched = data.batch_execute_statement(
        resourceArn=resource_arn, secretArn=secret_arn, database=_DB,
        sql=f"INSERT INTO {_TABLE} (id, {batch_names}) VALUES (:id, {batch_binds})",
        parameterSets=[[param("id", {"longValue": 3})]
                       + [param(col, {"stringValue": sent}, hint)
                          for col, hint, sent in batch_cols]],
    )
    assert _envelope(batched) == {"updateResults": [{"generatedFields": []}]}, (
        "a hinted batch must answer exactly one empty updateResults entry; got "
        f"{_envelope(batched)!r}"
    )
    batch_back = read(batch_names, 3)
    batch_expected = [[{"stringValue": _UUID}, {"stringValue": '{"z":1}'},
                       {"stringValue": "2026-01-02"}]]
    assert _envelope(batch_back) == {"records": batch_expected,
                                     "numberOfRecordsUpdated": 0}, (
        f"typeHint must apply inside a batch exactly as it does on a single statement; expected "
        f"{batch_expected!r}, got {_envelope(batch_back)!r}"
    )

    _refused(
        _refusal(lambda: data.batch_execute_statement(
            resourceArn=resource_arn, secretArn=secret_arn, database=_DB,
            sql=f"INSERT INTO {_TABLE} (id, u) VALUES (:id, :u)",
            parameterSets=[[param("id", {"longValue": 4}),
                            param("u", {"stringValue": "not-a-uuid"}, "UUID")]])),
        _BATCH_UUID,
        "a batched write whose hinted value cannot be parsed as a UUID",
    )
    after_batch_refusal = ids()
    assert after_batch_refusal == [1, 2, 3], (
        f"the refused batch must have written nothing, so row 4 must be absent; the table holds "
        f"ids {after_batch_refusal!r}"
    )


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A string parameter reaches a jsonb, uuid, timestamp, date, time or numeric column only
    with the matching typeHint; without it the engine refuses with SQLState 42804. A string its
    hint cannot parse is refused by the Data API itself, in a message carrying no SQLState.

    Reference: https://docs.aws.amazon.com/rdsdataservice/latest/APIReference/API_SqlParameter.html
    Reference: https://docs.aws.amazon.com/rdsdataservice/latest/APIReference/API_ExecuteStatement.html
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
