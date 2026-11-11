"""named-parameters-bind-literally-and-reject-unbound-placeholders."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "named-parameters-bind-literally-and-reject-unbound-placeholders"
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

_TABLE = "sim2real_behav_param_binding"

# Three payloads that are SQL if interpolated and data if bound. The second closes a quote and
# comments out the rest of the statement; the third would drop the table.
_QUOTE = "o'brien"
_TAUTOLOGY = "' or 1=1 --"
_DROP = "x'; DROP TABLE " + _TABLE + "; --"


def _grade(data, resource_arn, secret_arn) -> None:
    """Every assertion this check makes, against an already-provisioned Data API cluster."""

    def ex(sql, **kw):
        return data.execute_statement(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB, sql=sql, **kw)

    def insert(row_id, value, **kw):
        return ex(f"INSERT INTO {_TABLE} (id, v) VALUES (:id, :v)",
                  parameters=[{"name": "id", "value": {"longValue": row_id}},
                              {"name": "v", "value": {"stringValue": value}}], **kw)

    def value_of(row_id):
        rows = ex(f"SELECT v FROM {_TABLE} WHERE id = :id",
                  parameters=[{"name": "id", "value": {"longValue": row_id}}]).get("records") or []
        assert len(rows) == 1, f"expected exactly one row with id {row_id}; got {rows!r}"
        return rows[0][0].get("stringValue")

    def row_count():
        return ex(f"SELECT count(*) FROM {_TABLE}")["records"][0][0]["longValue"]

    ex(f"CREATE TABLE {_TABLE} (id int PRIMARY KEY, v text)")

    # --- (1) Bound parameters are VALUES. Each payload round-trips byte-for-byte, and the
    # table's shape is unchanged after all three.
    for row_id, payload, label in ((1, _QUOTE, "an apostrophe"),
                                   (2, _TAUTOLOGY, "a quote-closing tautology"),
                                   (3, _DROP, "a DROP TABLE payload")):
        insert(row_id, payload)
        got = value_of(row_id)
        assert got == payload, (
            f"{label} bound as a parameter must round-trip literally: expected {payload!r}, got "
            f"{got!r} — a target that interpolates parameters into the SQL text mangles or "
            f"executes it instead"
        )
    assert row_count() == 3, (
        f"exactly the three bound rows must exist — nothing extra was executed and nothing was "
        f"dropped; count is {row_count()}"
    )

    # --- (2) The payload is still data when it appears in a WHERE clause, which is where an
    # interpolating implementation would turn it into a tautology and match everything.
    matched = ex(f"SELECT count(*) FROM {_TABLE} WHERE v = :v",
                 parameters=[{"name": "v", "value": {"stringValue": _TAUTOLOGY}}]
                 )["records"][0][0]["longValue"]
    assert matched == 1, (
        f"comparing against {_TAUTOLOGY!r} as a bound value must match the one row holding that "
        f"exact text, not every row: got {matched} of {row_count()}"
    )

    # --- (3) Break exactly one thing: a placeholder with no matching parameter. The refusal is
    # specific, and the row is NOT written.
    unbound = _refusal(lambda: ex(
        f"INSERT INTO {_TABLE} (id, v) VALUES (:id, :missing)",
        parameters=[{"name": "id", "value": {"longValue": 90}}]))
    assert _code(unbound) == "ValidationException", (
        f"a placeholder with no parameter must be refused with ValidationException; got "
        f"{_code(unbound)!r}: {_message(unbound)!r}"
    )
    assert unbound.response["Error"]["Message"] == "Cannot find parameter: missing", (
        f"the refusal must NAME the unbound placeholder; got {_message(unbound)!r}"
    )
    assert row_count() == 3, (
        f"the rejected statement must not have written anything; count is {row_count()}"
    )

    # --- (4) The binder is ASYMMETRIC, and this is the over-permissiveness worth asserting: an
    # EXTRA parameter with no placeholder is accepted silently.
    accepted = ex(f"INSERT INTO {_TABLE} (id, v) VALUES (:id, :v)",
                  parameters=[{"name": "id", "value": {"longValue": 92}},
                              {"name": "v", "value": {"stringValue": "extra"}},
                              {"name": "unused", "value": {"stringValue": "no-placeholder"}}])
    assert accepted.get("numberOfRecordsUpdated") == 1, (
        f"a parameter with no matching placeholder must be IGNORED, not refused — the binder "
        f"rejects a missing binding and tolerates a surplus one, and an emulator symmetric in "
        f"both directions is wrong in one of them; got {accepted!r}"
    )
    assert value_of(92) == "extra", (
        f"the surplus parameter must not have displaced the bound one; got {value_of(92)!r}"
    )

    # --- (5) Two more specific refusals on the same surface, each with its own message.
    duplicate = _refusal(lambda: ex(
        f"INSERT INTO {_TABLE} (id, v) VALUES (:id, :v)",
        parameters=[{"name": "id", "value": {"longValue": 93}},
                    {"name": "v", "value": {"stringValue": "a"}},
                    {"name": "v", "value": {"stringValue": "b"}}]))
    assert _code(duplicate) == "ValidationException", (
        f"a repeated parameter name must be refused with ValidationException; got "
        f"{_code(duplicate)!r}: {_message(duplicate)!r}"
    )
    assert duplicate.response["Error"]["Message"] == "Duplicate parameter v", (
        f"the refusal must name the repeated parameter; got {_message(duplicate)!r}"
    )

    colon = _refusal(lambda: ex(
        f"SELECT :v AS v", parameters=[{"name": ":v", "value": {"stringValue": "a"}}]))
    assert _code(colon) == "ValidationException", (
        f"a parameter NAME carrying the ':' placeholder prefix must be refused with "
        f"ValidationException; got {_code(colon)!r}: {_message(colon)!r}"
    )
    assert colon.response["Error"]["Message"] == "Named parameter syntax is invalid, input: :v", (
        f"the refusal must distinguish bad NAME syntax from a missing binding; got "
        f"{_message(colon)!r}"
    )
    assert _message(colon) != _message(unbound), (
        f"a malformed parameter name and an unbound placeholder must not collapse to the same "
        f"message; both said {_message(unbound)!r}"
    )

    # --- (6) arrayValue is an arm of the Field union and the service refuses it as a PARAMETER
    # outright, while returning it happily as a RESULT. A model-driven emulator reads one
    # union and accepts it in both directions.
    array_param = _refusal(lambda: ex(
        f"SELECT :a AS a",
        parameters=[{"name": "a", "value": {"arrayValue": {"longValues": [1, 2, 3]}}}]))
    assert _code(array_param) == "ValidationException", (
        f"an arrayValue parameter must be refused with ValidationException even though "
        f"com.amazonaws.rdsdata#Field declares the arm; got {_code(array_param)!r}: "
        f"{_message(array_param)!r}"
    )
    assert array_param.response["Error"]["Message"] == "Array parameters are not supported.", (
        f"the refusal must say arrays are unsupported as parameters; got "
        f"{_message(array_param)!r}"
    )
    returned = ex("SELECT ARRAY[1,2,3]::int[] AS a")["records"][0][0]
    assert returned == {"arrayValue": {"longValues": [1, 2, 3]}}, (
        f"the SAME union arm must come BACK from a result — the direction is what is "
        f"unsupported, not the arm; got {returned!r}"
    )

    # --- (7) A typeHint carries a value the union has no arm for: DECIMAL is sent as a string
    # and stored as numeric, and comes back as a string.
    ex(f"ALTER TABLE {_TABLE} ADD COLUMN amount numeric(12,4)")
    ex(f"UPDATE {_TABLE} SET amount = :amount WHERE id = :id",
       parameters=[{"name": "id", "value": {"longValue": 1}},
                   {"name": "amount", "value": {"stringValue": "9.8765"},
                    "typeHint": "DECIMAL"}])
    amount = ex(f"SELECT amount FROM {_TABLE} WHERE id = :id",
                parameters=[{"name": "id", "value": {"longValue": 1}}]
                )["records"][0][0]
    assert amount == {"stringValue": "9.8765"}, (
        f"a DECIMAL typeHint must send the string through to a numeric column exactly and come "
        f"back in the stringValue arm; got {amount!r}"
    )

@tags("axis:rejection", "cap:c4", "concern:negative-classes", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Named parameters bind literally (an apostrophe, a tautology and a DROP TABLE payload
    round-trip as text, match one row and leave the table), a placeholder without a parameter is
    refused by name, and a parameter without a placeholder is ignored."""
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
