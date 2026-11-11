"""rds-data-column-metadata-members-and-result-set-options-under-json."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-data-column-metadata-members-and-result-set-options-under-json"
GROUP = "representation"
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
# ===== end shared helpers =====

_TABLE = "sim2real_behav_metadata"
_MONEY_TABLE = "sim2real_behav_metadata_money"

# The 14 ColumnMetadata members real AWS emits on every column of every result.
_MEMBERS = {
    "arrayBaseColumnType", "isAutoIncrement", "isCaseSensitive", "isCurrency", "isSigned",
    "label", "name", "nullable", "precision", "scale", "schemaName", "tableName", "type",
    "typeName",
}

# (column name, declared type, type, typeName, nullable, precision, scale, isSigned,
#  isCaseSensitive), every member as real AWS reported it.
_COLUMNS = [
    ("id", "serial PRIMARY KEY", 4, "serial", 0, 10, 0, True, False),
    ("nn", "text NOT NULL", 12, "text", 0, 2147483647, 0, False, True),
    ("nul", "text", 12, "text", 1, 2147483647, 0, False, True),
    ("num", "numeric(12,4)", 2, "numeric", 1, 12, 4, True, False),
    ("big", "int8", -5, "int8", 1, 19, 0, True, False),
    ("sm", "int2", 5, "int2", 1, 5, 0, True, False),
    ("fl", "float8", 8, "float8", 1, 17, 17, True, False),
    ("b", "bool", -7, "bool", 1, 1, 0, False, False),
    ("by", "bytea", -2, "bytea", 1, 2147483647, 0, False, True),
    ("tstz", "timestamptz", 1111, "timestamptz", 1, 35, 6, False, False),
    ("ts", "timestamp", 93, "timestamp", 1, 29, 6, False, False),
    ("dt", "date", 91, "date", 1, 13, 0, False, False),
    ("tm", "time", 92, "time", 1, 15, 6, False, False),
    ("arr", "int4[]", 2003, "_int4", 1, 10, 0, True, False),
    ("ch", "char(5)", 1, "bpchar", 1, 5, 0, False, True),
    ("vc", "varchar(7)", 12, "varchar", 1, 7, 0, False, True),
    ("u", "uuid", 1111, "uuid", 1, 2147483647, 0, False, True),
    ("j", "jsonb", 1111, "jsonb", 1, 2147483647, 0, False, True),
]

_MONEY_MSG = "The result contains the unsupported data type MONEY."
_MONEY = ("UnsupportedResultException", 400, _MONEY_MSG)

# One row whose two columns answer differently under each resultSetOptions setting: the numeric
# switches between a quoted string and a JSON number, the int8 between a number and a string.
_SHAPING_SQL = "SELECT numeric '123.4567' AS num, 9007199254740993::int8 AS big"
_SHAPING_FIELDS = {
    ("STRING", "LONG"): [{"stringValue": "123.4567"}, {"longValue": 9007199254740993}],
    ("STRING", "STRING"): [{"stringValue": "123.4567"}, {"stringValue": "9007199254740993"}],
    ("DOUBLE_OR_LONG", "LONG"): [{"doubleValue": 123.4567}, {"longValue": 9007199254740993}],
    ("DOUBLE_OR_LONG", "STRING"): [{"doubleValue": 123.4567},
                                   {"stringValue": "9007199254740993"}],
}
_SHAPING_JSON = {
    ("STRING", "LONG"): '[{"num":"123.4567","big":9007199254740993}]',
    ("STRING", "STRING"): '[{"num":"123.4567","big":"9007199254740993"}]',
    ("DOUBLE_OR_LONG", "LONG"): '[{"num":123.4567,"big":9007199254740993}]',
    ("DOUBLE_OR_LONG", "STRING"): '[{"num":123.4567,"big":"9007199254740993"}]',
}
_DEFAULT_OPTIONS = ("STRING", "LONG")


def _grade(data, resource_arn, secret_arn) -> None:
    """Every assertion this check makes, against an already-provisioned Data API cluster."""

    def ex(sql, **kw):
        return data.execute_statement(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB, sql=sql, **kw)

    def metadata(sql, what):
        resp = ex(sql, includeResultMetadata=True)
        meta = resp.get("columnMetadata")
        assert isinstance(meta, list) and meta, (
            f"{what} must answer a non-empty columnMetadata list when includeResultMetadata is "
            f"set; got {meta!r}"
        )
        return meta

    ex(f"CREATE TABLE {_TABLE} ("
       + ", ".join(f"{name} {decl}" for name, decl, *_ in _COLUMNS)
       + ")")
    ex(f"INSERT INTO {_TABLE} (nn) VALUES ('x')")

    names = [name for name, *_ in _COLUMNS]
    meta = metadata(f"SELECT {', '.join(names)} FROM {_TABLE}",
                    f"a SELECT of every column of {_TABLE}")
    assert len(meta) == len(_COLUMNS), (
        f"the result must carry one metadata entry per selected column; expected "
        f"{len(_COLUMNS)} for {names!r}, got {len(meta)}"
    )

    for entry, column in zip(meta, _COLUMNS):
        (name, decl, type_, type_name, nullable, precision, scale,
         is_signed, is_case_sensitive) = column
        missing = sorted(_MEMBERS - set(entry))
        assert not missing, (
            f"the metadata entry for the {decl} column {name!r} must carry all 14 "
            f"ColumnMetadata members {sorted(_MEMBERS)!r}; it lacks {missing!r} and carries "
            f"{sorted(entry, key=repr)!r}"
        )
        measured = {
            "name": name,
            "label": name,
            "type": type_,
            "typeName": type_name,
            "nullable": nullable,
            "scale": scale,
            "isSigned": is_signed,
            "isCaseSensitive": is_case_sensitive,
            "isAutoIncrement": name == "id",
            "isCurrency": False,
            "arrayBaseColumnType": 0,
            "schemaName": "",
            "tableName": _TABLE,
            "precision": precision,
        }
        reported = {member: entry.get(member) for member in measured}
        assert reported == measured, (
            f"the metadata for the {decl} column {name!r} must report {measured!r}; it reports "
            f"{reported!r}"
        )
        mistyped = {member: type(reported[member]).__name__ for member in measured
                    if type(reported[member]) is not type(measured[member])}
        assert not mistyped, (
            f"the metadata for the {decl} column {name!r} must carry each member in the JSON "
            f"type real AWS sends ({ {m: type(v).__name__ for m, v in measured.items()} !r}); "
            f"these arrive as {mistyped!r}"
        )

    aliased = metadata(
        f"SELECT id AS the_id, nn AS label_alias, num * 2 AS computed FROM {_TABLE}",
        "a SELECT with two aliased columns and one computed column",
    )
    assert len(aliased) == 3, (
        f"the result must carry one metadata entry per selected column; expected 3 for the two "
        f"aliases and the computed column, got {len(aliased)} ({aliased!r})"
    )
    assert [e.get("name") for e in aliased] == ["the_id", "label_alias", "computed"], (
        f"an alias must become the reported name; got "
        f"{[e.get('name') for e in aliased]!r}"
    )
    assert [e.get("label") for e in aliased] == ["the_id", "label_alias", "computed"], (
        f"an alias must change the label as well as the name, so label mirrors name; got "
        f"{[e.get('label') for e in aliased]!r}"
    )
    assert aliased[0].get("tableName") == _TABLE and aliased[0].get("typeName") == "serial", (
        f"aliasing a column must not detach it from its table or change its type; the alias of "
        f"the serial column reports tableName {aliased[0].get('tableName')!r} and typeName "
        f"{aliased[0].get('typeName')!r}"
    )
    computed = {member: aliased[2].get(member)
                for member in ("tableName", "precision", "nullable", "typeName")}
    assert computed == {"tableName": "", "precision": 0, "nullable": 1,
                        "typeName": "numeric"}, (
        f"a computed expression belongs to no table and carries no precision, unlike the column "
        f"it derives from; expected {{'tableName': '', 'precision': 0, 'nullable': 1, "
        f"'typeName': 'numeric'}}, got {computed!r}"
    )

    literals = metadata("SELECT 1 AS one, 'txt' AS two, NULL AS three",
                        "a SELECT of three literals")
    literal_shapes = [{member: e.get(member)
                       for member in ("name", "type", "typeName", "tableName", "nullable")}
                      for e in literals]
    expected_literals = [
        {"name": "one", "type": 4, "typeName": "int4", "tableName": "", "nullable": 1},
        {"name": "two", "type": 12, "typeName": "text", "tableName": "", "nullable": 1},
        {"name": "three", "type": 12, "typeName": "text", "tableName": "", "nullable": 1},
    ]
    assert literal_shapes == expected_literals, (
        f"a literal column belongs to no table and is reported nullable, and an untyped NULL is "
        f"reported as text; expected {expected_literals!r}, got {literal_shapes!r}"
    )

    joined = metadata(
        f"SELECT a.id, b.id FROM {_TABLE} a JOIN {_TABLE} b ON a.id = b.id",
        "a self-join selecting the same column from both sides",
    )
    assert [e.get("name") for e in joined] == ["id", "id"] and len(joined) == 2, (
        f"a self-join must return one metadata entry per selected column even when both carry "
        f"the same name, with nothing added to tell them apart; got "
        f"{[e.get('name') for e in joined]!r}"
    )
    assert [e.get("tableName") for e in joined] == [_TABLE, _TABLE], (
        f"both entries of the self-join must name the same table; got "
        f"{[e.get('tableName') for e in joined]!r}"
    )

    ex(f"CREATE TABLE {_MONEY_TABLE} (mny money)")
    ex(f"INSERT INTO {_MONEY_TABLE} (mny) VALUES ('12.34'::money)")
    for label, kw in (("in the column form", {}),
                      ("with formatRecordsAs JSON", {"formatRecordsAs": "JSON"})):
        _refused(
            _refusal(lambda k=kw: ex(f"SELECT mny FROM {_MONEY_TABLE}", **k)),
            _MONEY,
            f"a read of a money column {label}",
        )
    cast = ex(f"SELECT mny::numeric FROM {_MONEY_TABLE}", includeResultMetadata=True)
    assert cast.get("records") == [[{"stringValue": "12.34"}]], (
        f"the same cell must be readable once cast, which is what makes the refusal above a "
        f"property of the money type rather than of the row; got {cast.get('records')!r}"
    )
    cast_meta = {member: (cast.get("columnMetadata") or [{}])[0].get(member)
                 for member in ("typeName", "precision", "tableName")}
    assert cast_meta == {"typeName": "numeric", "precision": 0, "tableName": ""}, (
        f"the cast column must be reported as the numeric it became, with the precision and "
        f"tableName of a computed column; expected {{'typeName': 'numeric', 'precision': 0, "
        f"'tableName': ''}}, got {cast_meta!r}"
    )

    # The default leg below is the control: with no resultSetOptions the JSON form matches the
    # column (Field) form.
    for options, formatted in _SHAPING_JSON.items():
        decimal_type, long_type = options
        resp = ex(
            _SHAPING_SQL, formatRecordsAs="JSON",
            resultSetOptions={"decimalReturnType": decimal_type, "longReturnType": long_type})
        assert _envelope(resp) == {"numberOfRecordsUpdated": 0,
                                   "formattedRecords": formatted}, (
            f"resultSetOptions must be honoured under formatRecordsAs JSON rather than ignored: "
            f"decimalReturnType {decimal_type} and longReturnType {long_type} must produce "
            f"{formatted!r}; got {_envelope(resp)!r}"
        )

    json_default = ex(_SHAPING_SQL, formatRecordsAs="JSON")
    assert _envelope(json_default) == {
        "numberOfRecordsUpdated": 0,
        "formattedRecords": _SHAPING_JSON[_DEFAULT_OPTIONS],
    }, (
        f"omitting resultSetOptions under JSON must behave as decimalReturnType "
        f"{_DEFAULT_OPTIONS[0]} with longReturnType {_DEFAULT_OPTIONS[1]}, producing "
        f"{_SHAPING_JSON[_DEFAULT_OPTIONS]!r}; got {_envelope(json_default)!r}"
    )
    field_default = ex(_SHAPING_SQL)
    assert _envelope(field_default) == {
        "records": [_SHAPING_FIELDS[_DEFAULT_OPTIONS]],
        "numberOfRecordsUpdated": 0,
    }, (
        f"omitting resultSetOptions in the column form must behave the same way, producing "
        f"{_SHAPING_FIELDS[_DEFAULT_OPTIONS]!r}; got {_envelope(field_default)!r}"
    )


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:negative-classes", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Every ColumnMetadata entry carries all 14 members (empty schemaName, zero arrayBaseColumnType
    even for an array, type 1111 for uuid, jsonb and timestamptz); resultSetOptions pick the JSON
    scalar form, and a MONEY column is refused with UnsupportedResultException in both forms.

    Reference: https://docs.aws.amazon.com/rdsdataservice/latest/APIReference/API_ColumnMetadata.html
    Reference: https://docs.aws.amazon.com/rdsdataservice/latest/APIReference/API_ResultSetOptions.html
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
