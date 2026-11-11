"""typed-value-round-trip."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "typed-value-round-trip"
GROUP = 'representation'
SERVICES = ['rds-data']

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
# Cluster-delete retries and the subnet-group wait; all teardowns share an 1800 s cleanup budget.
_CLUSTER_RETRY_S = 300
_SUBNET_GROUP_WAIT_S = 600


# ===== helpers =====


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
# ===== end helpers =====

_TABLE = "sim2real_behav_field_arms"

# alias, postgres column type, the literal inserted, the Field union arm the Data API must
# answer with, and the exact value (aurora-postgresql 17.7, Data API v2, default
# resultSetOptions). `None` marks a row whose value is asserted structurally below rather than
# by equality.
_COLUMNS = [
    ("c_int4", "int4", "1", "longValue", 1),
    # 2**53 + 1: not representable as an IEEE-754 double, so an emulator that routes every
    # integer through a float loses the low bit here and nowhere else.
    ("c_int8", "int8", "9007199254740993", "longValue", 9007199254740993),
    ("c_int2", "smallint", "7", "longValue", 7),
    ("c_text", "text", "'hello'", "stringValue", "hello"),
    # NUMERIC comes back as a STRING, not a doubleValue: the Data API refuses to lose
    # precision, and this is the single most-guessed-wrong arm in the union.
    ("c_numeric", "numeric(12,4)", "123.4567", "stringValue", "123.4567"),
    ("c_float8", "double precision", "2.5", "doubleValue", 2.5),
    ("c_real", "real", "1.5", "doubleValue", 1.5),
    ("c_bool", "boolean", "true", "booleanValue", True),
    ("c_null", "text", "NULL", "isNull", True),
    ("c_bytea", "bytea", "'\\x0102ff'::bytea", "blobValue", b"\x01\x02\xff"),
    ("c_ts", "timestamp", "'2026-09-11 03:04:05'", "stringValue", "2026-09-11 03:04:05"),
    ("c_tstz", "timestamptz", "'2026-09-11T03:04:05.123456Z'", "stringValue", None),
    ("c_date", "date", "'2026-09-11'", "stringValue", "2026-09-11"),
    ("c_uuid", "uuid", "'11111111-2222-3333-4444-555555555555'", "stringValue",
     "11111111-2222-3333-4444-555555555555"),
    # Deliberately spaced. Postgres stores a `json` column's text VERBATIM, but the Data API
    # hands back a compacted re-serialisation — see the attribution block below, where the text
    # column holding the identical characters is the control.
    ("c_json", "json", "'{ \"a\" : 1 , \"b\" : [ 2 , 3 ] }'", "stringValue",
     '{"a":1,"b":[2,3]}'),
    ("c_jsontext", "text", "'{ \"a\" : 1 , \"b\" : [ 2 , 3 ] }'", "stringValue",
     '{ "a" : 1 , "b" : [ 2 , 3 ] }'),
    ("c_array", "int[]", "ARRAY[1,2,3]", "arrayValue", {"longValues": [1, 2, 3]}),
]


def _grade(data, resource_arn, secret_arn) -> None:
    """Every assertion this check makes, against an already-provisioned Data API cluster."""
    import re

    def ex(sql, **kw):
        return data.execute_statement(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB, sql=sql, **kw)

    cols = ", ".join(f"{alias} {pg}" for alias, pg, _, _, _ in _COLUMNS)
    ex(f"CREATE TABLE {_TABLE} ({cols})")
    values = ", ".join(literal for _, _, literal, _, _ in _COLUMNS)
    inserted = ex(f"INSERT INTO {_TABLE} VALUES ({values})")
    assert inserted.get("numberOfRecordsUpdated") == 1, (
        f"the insert must report exactly one row written; got "
        f"{inserted.get('numberOfRecordsUpdated')!r} in {inserted!r}"
    )
    assert inserted.get("generatedFields") == [], (
        f"a plain INSERT with no identity column must report an EMPTY generatedFields list, "
        f"present rather than absent; got {inserted.get('generatedFields')!r}"
    )
    assert "records" not in inserted, (
        f"an INSERT must not carry a records list; got keys {sorted(inserted)!r}"
    )

    select = ", ".join(alias for alias, _, _, _, _ in _COLUMNS)
    resp = ex(f"SELECT {select} FROM {_TABLE}")
    records = resp.get("records") or []
    assert len(records) == 1, f"expected exactly the one inserted row; got {records!r}"
    row = records[0]
    assert len(row) == len(_COLUMNS), (
        f"the record must hold one Field per selected column: expected {len(_COLUMNS)}, got "
        f"{len(row)} ({row!r})"
    )
    assert resp.get("numberOfRecordsUpdated") == 0, (
        f"a SELECT must still report numberOfRecordsUpdated=0 rather than omitting it; got "
        f"{resp.get('numberOfRecordsUpdated')!r}"
    )
    assert "columnMetadata" not in resp, (
        f"columnMetadata must be absent unless includeResultMetadata was asked for; got keys "
        f"{sorted(resp)!r}"
    )

    for field, (alias, pg, _, arm, expected) in zip(row, _COLUMNS):
        assert isinstance(field, dict) and len(field) == 1, (
            f"{alias} ({pg}): a Field is a tagged union and must carry EXACTLY one arm; got "
            f"{field!r}"
        )
        assert arm in field, (
            f"{alias} ({pg}) must be returned in the {arm!r} arm of the Field union; got "
            f"{field!r} — an emulator that picks a different arm changes the type every caller "
            f"deserialises"
        )
        if expected is not None:
            assert field[arm] == expected, (
                f"{alias} ({pg}) must round-trip to {expected!r} in {arm!r}; got {field[arm]!r}"
            )

    # timestamptz is the one column whose exact text depends on the cluster's session zone, so
    # it is graded on the property that actually matters: the Data API FLATTENS it to a naive
    # string with a space separator and no zone at all, so the offset a caller sent is gone.
    tstz = row[[c[0] for c in _COLUMNS].index("c_tstz")]["stringValue"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?", tstz), (
        f"timestamptz must come back as 'YYYY-MM-DD HH:MM:SS[.ffffff]' — a space separator, no "
        f"'T', and NO zone designator or offset, which is how the Data API loses the zone; got "
        f"{tstz!r}"
    )
    assert "T" not in tstz and "+" not in tstz and not tstz.endswith("Z"), (
        f"timestamptz must not be returned in ISO-8601 form: no 'T', no offset, no trailing 'Z'; "
        f"got {tstz!r}"
    )

    # The NULL arm is exactly {"isNull": true} — never a stringValue of "" or "NULL".
    null_field = row[[c[0] for c in _COLUMNS].index("c_null")]
    assert null_field == {"isNull": True}, (
        f"a SQL NULL must be exactly {{'isNull': True}}; got {null_field!r}"
    )

    # --- A `json` column is RE-SERIALISED on the way out. The engine kept the caller's
    # whitespace — proved by casting the same column to text, which the Data API passes through
    # verbatim — and the Field arm carries a compacted form instead. The text column holding the
    # IDENTICAL characters is the control, so the compaction is attributable to the json type and
    # not to the transport.
    at = [c[0] for c in _COLUMNS].index
    stored = ex(f"SELECT c_json::text FROM {_TABLE}")["records"][0][0]["stringValue"]
    assert stored == row[at("c_jsontext")]["stringValue"], (
        f"casting the json column to text must return the caller's own spacing, byte-for-byte "
        f"equal to the text column holding the same characters: got {stored!r} vs "
        f"{row[at('c_jsontext')]['stringValue']!r}"
    )
    assert row[at("c_json")]["stringValue"] != stored, (
        f"a json column must NOT be returned as its stored text — the Data API re-serialises "
        f"it, and an emulator that passes the stored text through disagrees with real AWS; both "
        f"were {stored!r}"
    )
    assert row[at("c_json")]["stringValue"] == '{"a":1,"b":[2,3]}', (
        f"the re-serialisation is compaction: no space after ':' or ',' anywhere; got "
        f"{row[at('c_json')]['stringValue']!r}"
    )

    # --- columnMetadata: only on request, and it carries the DECLARED precision/scale that the
    # stringValue arm exists to preserve.
    meta_resp = ex(f"SELECT {select} FROM {_TABLE}", includeResultMetadata=True)
    meta = meta_resp.get("columnMetadata") or []
    assert [m.get("name") for m in meta] == [c[0] for c in _COLUMNS], (
        f"columnMetadata must name every selected column in order; got "
        f"{[m.get('name') for m in meta]!r}"
    )
    numeric_meta = meta[[c[0] for c in _COLUMNS].index("c_numeric")]
    assert numeric_meta.get("typeName") == "numeric", (
        f"the numeric column's metadata must report the engine's own type name; got "
        f"{numeric_meta.get('typeName')!r}"
    )
    assert (numeric_meta.get("precision"), numeric_meta.get("scale")) == (12, 4), (
        f"numeric(12,4) must report precision 12 and scale 4 — this is the information the "
        f"stringValue arm exists to preserve; got "
        f"{(numeric_meta.get('precision'), numeric_meta.get('scale'))!r}"
    )

    # --- resultSetOptions move a column between arms. Both overrides are lossy on purpose, and
    # an emulator that ignores them silently answers the default arm.
    as_double = ex(f"SELECT c_numeric FROM {_TABLE}",
                   resultSetOptions={"decimalReturnType": "DOUBLE_OR_LONG"})
    assert as_double["records"][0][0] == {"doubleValue": 123.4567}, (
        f"decimalReturnType=DOUBLE_OR_LONG must move numeric out of stringValue and into "
        f"doubleValue; got {as_double['records'][0][0]!r}"
    )
    as_string = ex(f"SELECT c_int8 FROM {_TABLE}",
                   resultSetOptions={"longReturnType": "STRING"})
    assert as_string["records"][0][0] == {"stringValue": "9007199254740993"}, (
        f"longReturnType=STRING must move int8 out of longValue and into stringValue; got "
        f"{as_string['records'][0][0]!r}"
    )

    # --- The union is NOT total. Two result values have no arm at all, and each is a typed
    # refusal rather than a stringified fallback: an emulator that returns SOMETHING here is
    # more permissive than real AWS.
    interval = _refusal(lambda: ex("SELECT '1 day'::interval AS iv"))
    assert _code(interval) == "UnsupportedResultException", (
        f"an INTERVAL result has no Field arm and must be refused with the modelled "
        f"UnsupportedResultException; got {_code(interval)!r}: {_message(interval)!r}"
    )
    assert interval.response["Error"]["Message"] == "The result contains the unsupported data type INTERVAL.", (
        f"the refusal must name the offending type; got {_message(interval)!r}"
    )
    infinity = _refusal(lambda: ex("SELECT 'inf'::float8 AS inf"))
    assert _code(infinity) == "UnsupportedResultException", (
        f"a non-finite double has no representable value and must be refused with "
        f"UnsupportedResultException; got {_code(infinity)!r}: {_message(infinity)!r}"
    )
    assert infinity.response["Error"]["Message"] == "NaN and Infinity values are not supported", (
        f"the non-finite refusal must be distinguishable from the unsupported-type one; got "
        f"{_message(infinity)!r}"
    )
    assert _message(infinity) != _message(interval), (
        f"the two UnsupportedResultException cases must not collapse to one message: both said "
        f"{_message(interval)!r}"
    )

@tags("axis:happy-path", "cap:c3", "concern:representation", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Each postgres type read back through the Data API maps to ONE specific Field union arm, two
    resultSetOptions move a column between arms, and INTERVAL and a non-finite double are typed
    refusals rather than stringified fallbacks."""
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
