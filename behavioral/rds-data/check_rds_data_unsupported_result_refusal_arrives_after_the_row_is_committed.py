"""rds-data-unsupported-result-refusal-arrives-after-the-row-is-committed."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-data-unsupported-result-refusal-arrives-after-the-row-is-committed"
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

_TABLE = "sim2real_behav_refusal_after_write"

# Byte-exact messages real AWS returned for each graded refusal.
_MULTIDIM_MSG = "The result contains a multidimensional array."
_INTERVAL_MSG = "The result contains the unsupported data type INTERVAL."
_NAN_MSG = "NaN and Infinity values are not supported"
_SIZE_MSG = "The result exceeds the size limit 1 MB."
_SQL_LEN_MSG = "Number of characters in SQLStatement is longer than 65536"

# Each graded refusal as the code, HTTP status and exact message real AWS answered it with.
_MULTIDIM = ("UnsupportedResultException", 400, _MULTIDIM_MSG)
_INTERVAL = ("UnsupportedResultException", 400, _INTERVAL_MSG)
_NAN = ("UnsupportedResultException", 400, _NAN_MSG)
_TOO_BIG = ("UnsupportedResultException", 400, _SIZE_MSG)
_SQL_TOO_LONG = ("ValidationException", 400, _SQL_LEN_MSG)

# The literal real AWS echoed back in the message it returns for a secretArn that is not an ARN,
# so the input and the expected message are derived from one constant.
_NOT_AN_ARN = "not-an-arn-x"

# A single cell of this width exceeds the Data API's 1 MB result-size limit on its own.
_OVERSIZE_CHARS = 1_100_000

# Padding that carries the statement past the 65 536 character ceiling on `sql` without making
# the statement itself mean anything different.
_SQL_PADDING = 70_000


def _grade(data, resource_arn, secret_arn) -> None:
    """Every assertion this check makes, against an already-provisioned Data API cluster."""

    def ex(sql, **kw):
        return data.execute_statement(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB, sql=sql, **kw)

    def ids():
        resp = ex(f"SELECT id FROM {_TABLE} ORDER BY id")
        return [r[0]["longValue"] for r in resp.get("records") or []]

    def insert(id_, columns, values, returning, **kw):
        return ex(
            f"INSERT INTO {_TABLE} (id, {columns}) VALUES ({id_}, {values}) "
            f"RETURNING {returning}",
            **kw,
        )

    ex(f"CREATE TABLE {_TABLE} (id int PRIMARY KEY, arr int[][], iv interval, "
       f"dbl float8, txt text)")
    empty = ids()
    assert empty == [], (
        f"the table must start empty so every later row is attributable to one statement; it "
        f"holds ids {empty!r}"
    )

    supported = insert(1, "dbl, txt", "1.5, 'ok'", "id")
    assert _envelope(supported) == {"records": [[{"longValue": 1}]],
                                    "numberOfRecordsUpdated": 0}, (
        "an accepted INSERT ... RETURNING id must answer the returned row in `records` with "
        "numberOfRecordsUpdated 0 and no generatedFields key, exactly "
        "{'records': [[{'longValue': 1}]], 'numberOfRecordsUpdated': 0}; got "
        f"{_envelope(supported)!r}"
    )
    landed = [1]
    after_supported = ids()
    assert after_supported == landed, (
        f"the accepted INSERT must have written exactly row 1; the table holds "
        f"{after_supported!r}"
    )

    _refused(
        _refusal(lambda: insert(2, "arr", "ARRAY[[1,2],[3,4]]", "arr")),
        _MULTIDIM,
        "an INSERT ... RETURNING whose returned column is a multidimensional array",
    )
    landed = landed + [2]
    after_multidim = ids()
    assert after_multidim == landed, (
        f"the refusal is raised while shaping the result, after the row was already committed, "
        f"so row 2 must be present; expected ids {landed!r}, got {after_multidim!r}"
    )

    _refused(
        _refusal(lambda: insert(3, "iv", "interval '1 day'", "iv")),
        _INTERVAL,
        "an INSERT ... RETURNING whose returned column is an interval",
    )
    landed = landed + [3]
    after_interval = ids()
    assert after_interval == landed, (
        f"the interval refusal must also leave its row committed; expected ids {landed!r}, got "
        f"{after_interval!r}"
    )

    _refused(
        _refusal(lambda: insert(4, "dbl", "'NaN'::float8", "dbl")),
        _NAN,
        "an INSERT ... RETURNING whose returned column holds NaN",
    )
    landed = landed + [4]
    after_nan = ids()
    assert after_nan == landed, (
        f"the NaN refusal must also leave its row committed; expected ids {landed!r}, got "
        f"{after_nan!r}"
    )

    rescued = insert(5, "dbl", "'NaN'::float8", "dbl", formatRecordsAs="JSON")
    assert _envelope(rescued) == {"numberOfRecordsUpdated": 0,
                                  "formattedRecords": '[{"dbl":"NaN"}]'}, (
        "asking for JSON records must rescue the same NaN result the column form refuses, "
        "answering exactly {'numberOfRecordsUpdated': 0, 'formattedRecords': "
        "'[{\"dbl\":\"NaN\"}]'}; got "
        f"{_envelope(rescued)!r}"
    )
    landed = landed + [5]
    after_rescued = ids()
    assert after_rescued == landed, (
        f"the rescued INSERT must have written row 5; expected ids {landed!r}, got "
        f"{after_rescued!r}"
    )

    _refused(
        _refusal(lambda: insert(6, "arr", "ARRAY[[5,6],[7,8]]", "arr", formatRecordsAs="JSON")),
        _MULTIDIM,
        "an INSERT ... RETURNING of a multidimensional array with formatRecordsAs JSON",
    )
    landed = landed + [6]
    after_json_multidim = ids()
    assert after_json_multidim == landed, (
        f"JSON records do not rescue a multidimensional array, and the refusal still arrives "
        f"after the row is committed; expected ids {landed!r}, got {after_json_multidim!r}"
    )

    _refused(
        _refusal(lambda: ex(f"SELECT iv FROM {_TABLE} WHERE id = 3", formatRecordsAs="JSON")),
        _INTERVAL,
        "a read of an interval column with formatRecordsAs JSON",
    )

    _refused(
        _refusal(lambda: insert(7, "txt", f"repeat('x', {_OVERSIZE_CHARS})", "txt")),
        _TOO_BIG,
        "an INSERT ... RETURNING whose returned cell exceeds the result size limit",
    )
    landed = landed + [7]
    after_size = ids()
    assert after_size == landed, (
        f"the size refusal must also leave its row committed; expected ids {landed!r}, got "
        f"{after_size!r}"
    )
    _refused(
        _refusal(lambda: ex(f"SELECT txt FROM {_TABLE} WHERE id = 7", formatRecordsAs="JSON")),
        _TOO_BIG,
        "a read of the oversized cell with formatRecordsAs JSON",
    )

    cast = ex(f"SELECT arr::text FROM {_TABLE} WHERE id = 2")
    assert _envelope(cast) == {"records": [[{"stringValue": "{{1,2},{3,4}}"}]],
                               "numberOfRecordsUpdated": 0}, (
        "casting the committed multidimensional array to text must return it intact, which is "
        "what proves the refused statement wrote the value and not merely a row; got "
        f"{_envelope(cast)!r}"
    )

    # The same unrepresentable result on a statement that carries no write payload. What this
    # leg grades is the refusal itself: it is identical to the one the INSERT above drew, which
    # is what makes the committed row there a property of the write and not of the message.
    _refused(
        _refusal(lambda: ex("SELECT ARRAY[[9,9],[9,9]]")),
        _MULTIDIM,
        "a read-only SELECT of a multidimensional array literal",
    )

    doomed_insert = f"INSERT INTO {_TABLE} (id, txt) VALUES (8, 'padded')"
    _refused(
        _refusal(lambda: ex(f"{doomed_insert} /*{'x' * _SQL_PADDING}*/")),
        _SQL_TOO_LONG,
        "a statement whose sql exceeds the character ceiling",
    )
    after_too_long = ids()
    assert after_too_long == landed, (
        f"a statement refused for its length must not run, so unlike the result refusals above "
        f"its row must be absent; expected ids {landed!r}, got {after_too_long!r}"
    )

    _refused(
        _refusal(lambda: data.execute_statement(
            resourceArn=resource_arn, secretArn=_NOT_AN_ARN, database=_DB,
            sql=f"INSERT INTO {_TABLE} (id, txt) VALUES (9, 'bad-secret')")),
        ("ValidationException", 400, f"Invalid secret arn: {_NOT_AN_ARN}"),
        "a write whose secretArn is not an ARN",
    )
    after_bad_secret = ids()
    assert after_bad_secret == landed, (
        f"a write refused for an unparseable secretArn must not run; expected ids {landed!r}, "
        f"got {after_bad_secret!r}"
    )

    ex(doomed_insert)
    ex(f"INSERT INTO {_TABLE} (id, txt) VALUES (9, 'bad-secret')")
    replayed = ids()
    assert replayed == landed + [8, 9], (
        f"replaying both suppressed writes must land them, proving the two refusals above held "
        f"back statements that the engine would otherwise have applied; expected ids "
        f"{landed + [8, 9]!r}, got {replayed!r}"
    )


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """An INSERT ... RETURNING whose returned value the Data API cannot represent is refused
    after the row has been committed, and asking for JSON records rescues only the NaN case.
    A statement refused for its own length or an unparseable secretArn never runs at all.

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
