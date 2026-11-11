"""formatted-json-records-match-column-records."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "formatted-json-records-match-column-records"
GROUP = 'representation'
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

_TABLE = "sim2real_behav_json_form"


def _grade(data, resource_arn, secret_arn) -> None:
    """Every assertion this check makes, against an already-provisioned Data API cluster."""
    import base64
    import json

    def ex(sql, **kw):
        return data.execute_statement(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB, sql=sql, **kw)

    ex(f"CREATE TABLE {_TABLE} (id int8, amount numeric(12,4), payload bytea, "
       f"note text, tags int[])")
    ex(f"INSERT INTO {_TABLE} VALUES (9007199254740993, 123.4567, '\\x0102ff'::bytea, "
       f"NULL, ARRAY[1,2,3])")

    sql = f"SELECT id, amount, payload, note, tags FROM {_TABLE}"

    # --- The default form: positional Fields, and NO column names anywhere in the response.
    default = ex(sql)
    assert "records" in default and "formattedRecords" not in default, (
        f"the default response form is `records`; got keys {sorted(default)!r}"
    )
    row = default["records"][0]
    assert len(row) == 5, f"expected five positional Fields; got {row!r}"
    assert "columnMetadata" not in default, (
        f"the default form carries no column names at all — that is what formatRecordsAs=JSON "
        f"and includeResultMetadata each add; got keys {sorted(default)!r}"
    )

    # formatRecordsAs=NONE must be exactly the default, not a third form.
    none_form = ex(sql, formatRecordsAs="NONE")
    assert none_form.get("records") == default["records"], (
        f"formatRecordsAs=NONE must be identical to the default: expected "
        f"{default['records']!r}, got {none_form.get('records')!r}"
    )
    assert "formattedRecords" not in none_form, (
        f"formatRecordsAs=NONE must not produce formattedRecords; got keys {sorted(none_form)!r}"
    )

    # --- The JSON form REPLACES records with a single string, and adds the column names.
    js = ex(sql, formatRecordsAs="JSON")
    assert "formattedRecords" in js and "records" not in js, (
        f"formatRecordsAs=JSON must replace `records` with `formattedRecords`, not add to it; "
        f"got keys {sorted(js)!r}"
    )
    assert isinstance(js["formattedRecords"], str), (
        f"formattedRecords is a JSON STRING the caller parses, not a parsed structure; got "
        f"{type(js['formattedRecords']).__name__}"
    )
    parsed = json.loads(js["formattedRecords"])
    assert isinstance(parsed, list) and len(parsed) == 1, (
        f"formattedRecords must decode to a list of one object per row; got {parsed!r}"
    )
    obj = parsed[0]
    assert list(obj) == ["id", "amount", "payload", "note", "tags"], (
        f"the JSON form keys each value by its COLUMN NAME, in select order — the information "
        f"the positional form omits; got {list(obj)!r}"
    )

    # --- The two forms describe the same row but ENCODE three of the five values differently.
    # This is the whole claim, and no single envelope carries it.
    assert row[0] == {"longValue": 9007199254740993}, (
        f"int8 must be exact in the positional form; got {row[0]!r}"
    )
    assert obj["id"] == 9007199254740993 and isinstance(obj["id"], int), (
        f"int8 must stay an exact JSON integer in the formatted form too, not a float; got "
        f"{obj['id']!r}"
    )

    assert row[1] == {"stringValue": "123.4567"}, (
        f"numeric must be a stringValue in the positional form; got {row[1]!r}"
    )
    assert obj["amount"] == "123.4567", (
        f"numeric must ALSO be a JSON string in the formatted form — both forms refuse to turn "
        f"it into a float; got {obj['amount']!r}"
    )

    assert row[2] == {"blobValue": b"\x01\x02\xff"}, (
        f"bytea must be raw bytes in the positional form; got {row[2]!r}"
    )
    assert obj["payload"] == "AQL/", (
        f"bytea must be BASE64 in the formatted form — JSON has no byte type, so this is where "
        f"the two forms genuinely diverge; got {obj['payload']!r}"
    )
    assert base64.b64decode(obj["payload"]) == row[2]["blobValue"], (
        f"the two encodings must describe the same bytes: base64 {obj['payload']!r} decodes to "
        f"{base64.b64decode(obj['payload'])!r}, positional form holds {row[2]['blobValue']!r}"
    )

    assert row[3] == {"isNull": True}, (
        f"a NULL must be the isNull arm in the positional form; got {row[3]!r}"
    )
    assert "note" in obj and obj["note"] is None, (
        f"a NULL must be a JSON null that is PRESENT under its column name in the formatted "
        f"form — omitting the key would be a different claim; got {obj!r}"
    )

    assert row[4] == {"arrayValue": {"longValues": [1, 2, 3]}}, (
        f"an int[] column must be the arrayValue arm in the positional form; got {row[4]!r}"
    )
    assert obj["tags"] == [1, 2, 3], (
        f"an int[] column must flatten to a plain JSON array in the formatted form; got "
        f"{obj['tags']!r}"
    )

    # --- includeResultMetadata is SILENTLY DROPPED under JSON formatting. Asking for both is
    # not an error and not honoured, which is the kind of thing only a comparison reveals.
    both = ex(sql, formatRecordsAs="JSON", includeResultMetadata=True)
    assert "formattedRecords" in both, (
        f"asking for JSON records AND metadata must still return the JSON records; got keys "
        f"{sorted(both)!r}"
    )
    assert "columnMetadata" not in both, (
        f"includeResultMetadata must be silently IGNORED under formatRecordsAs=JSON — not "
        f"honoured, and not an error; got keys {sorted(both)!r}"
    )
    meta_only = ex(sql, includeResultMetadata=True)
    assert [m["name"] for m in meta_only["columnMetadata"]] == [
        "id", "amount", "payload", "note", "tags"
    ], (
        f"the same request WITHOUT formatRecordsAs must honour includeResultMetadata, which is "
        f"what makes the drop above attributable to the JSON form alone; got "
        f"{meta_only.get('columnMetadata')!r}"
    )

@tags("axis:happy-path", "cap:c3", "concern:representation", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """One row read four ways: formatRecordsAs=JSON returns one JSON string with column names
    (bytea as base64, numeric as a string, int8 exact past 2**53, NULL as JSON null) in place of
    `records`, and it drops includeResultMetadata, which the plain form honors."""
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
