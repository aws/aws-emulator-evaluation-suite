"""rejects-bad-resource-secret-and-database-with-distinct-codes."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rejects-bad-resource-secret-and-database-with-distinct-codes"
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

_TABLE = "sim2real_behav_rejection_taxonomy"


def _grade(data, resource_arn, secret_arn, region, account) -> None:
    """Every assertion this check makes, against an already-provisioned Data API cluster."""
    absent_cluster = f"arn:aws:rds:{region}:{account}:cluster:sim2real-behav-rdsdata-absent"
    absent_secret = (f"arn:aws:secretsmanager:{region}:{account}:secret:"
                     f"sim2real-behav-rdsdata-absent-AbCdEf")
    not_an_arn = "sim2real-behav-rdsdata-not-an-arn"

    def ex(sql, **kw):
        return data.execute_statement(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB, sql=sql, **kw)

    def call(**over):
        kw = {"resourceArn": resource_arn, "secretArn": secret_arn, "database": _DB,
              "sql": "SELECT 1"}
        kw.update(over)
        return lambda: data.execute_statement(**kw)

    def row_count():
        return ex(f"SELECT count(*) FROM {_TABLE}")["records"][0][0]["longValue"]

    # --- (0) The positive control: the fully-correct call succeeds, so every refusal below is
    # attributable to the one field it changes.
    ok = call()()
    assert ok["records"] == [[{"longValue": 1}]], (
        f"the control statement must succeed and return one longValue; got {ok!r}"
    )
    ex(f"CREATE TABLE {_TABLE} (id int PRIMARY KEY)")
    ex(f"INSERT INTO {_TABLE} (id) VALUES (1)")
    assert row_count() == 1, f"control table must hold its one row; count is {row_count()}"

    codes = {}

    # --- (1) A well-formed ARN naming no Data-API cluster: the resource error, not a not-found.
    bad_cluster = _refusal(call(resourceArn=absent_cluster))
    codes["absent cluster"] = _code(bad_cluster)
    assert _code(bad_cluster) == "HttpEndpointNotEnabledException", (
        f"a well-formed cluster ARN that resolves to nothing must be refused with the modelled "
        f"HttpEndpointNotEnabledException — the Data API reports the ENDPOINT as not enabled "
        f"rather than the cluster as absent, which is the surprising part; got "
        f"{_code(bad_cluster)!r}: {_message(bad_cluster)!r}"
    )
    assert bad_cluster.response["Error"]["Message"] == (
        f"HttpEndpoint is not enabled for resource {absent_cluster}."
    ), f"the refusal must quote the ARN it could not use; got {_message(bad_cluster)!r}"

    # --- (2) A resourceArn that is not an ARN at all is a DIFFERENT code: syntax before lookup.
    malformed = _refusal(call(resourceArn=not_an_arn))
    codes["malformed cluster arn"] = _code(malformed)
    assert _code(malformed) == "ValidationException", (
        f"a resourceArn that is not an ARN must be refused with ValidationException, not the "
        f"resource error; got {_code(malformed)!r}: {_message(malformed)!r}"
    )
    assert malformed.response["Error"]["Message"] == f"Invalid cluster arn: {not_an_arn}", (
        f"the syntax refusal must quote the offending value; got {_message(malformed)!r}"
    )

    # --- (3) A well-formed but absent SECRET, with the cluster left correct: a third code.
    bad_secret = _refusal(call(secretArn=absent_secret))
    codes["absent secret"] = _code(bad_secret)
    assert _code(bad_secret) == "SecretsErrorException", (
        f"an absent credential secret must be refused with the modelled SecretsErrorException, "
        f"distinct from every resource and database error; got {_code(bad_secret)!r}: "
        f"{_message(bad_secret)!r}"
    )
    assert bad_secret.response["Error"]["Message"] == f"The secret {absent_secret} wasn't found.", (
        f"the refusal must quote the secret it looked for; got {_message(bad_secret)!r}"
    )

    # --- (4) Precedence: with BOTH the cluster and the secret bad, the CLUSTER is reported. The
    # order is fixed, and only a comparison of these three calls establishes it.
    both_bad = _refusal(call(resourceArn=absent_cluster, secretArn=absent_secret))
    assert _code(both_bad) == "HttpEndpointNotEnabledException", (
        f"the cluster is resolved BEFORE the secret, so a request with both broken must report "
        f"the cluster: got {_code(both_bad)!r}: {_message(both_bad)!r}"
    )
    assert both_bad.response["Error"]["Message"] == _message(bad_cluster), (
        f"the both-broken message must be exactly the cluster-only one, which is what makes the "
        f"ordering claim falsifiable; got {_message(both_bad)!r}"
    )

    # --- (5) A database that does not exist reaches the ENGINE, and its SQLSTATE comes back.
    bad_db = _refusal(call(database="sim2real_behav_no_such_db"))
    codes["absent database"] = _code(bad_db)
    assert _code(bad_db) == "DatabaseErrorException", (
        f"an absent database must be refused with DatabaseErrorException — the request got as "
        f"far as the engine; got {_code(bad_db)!r}: {_message(bad_db)!r}"
    )
    assert bad_db.response["Error"]["Message"] == (
        'ERROR: database "sim2real_behav_no_such_db" does not exist; SQLState: 3D000'
    ), (
        f"the engine's own message and invalid-catalog-name SQLSTATE must reach the caller; got "
        f"{_message(bad_db)!r}"
    )

    # --- (6) A SQL syntax error is the same code with a different SQLSTATE and the engine's own
    # wording, including the character position. An emulator that returns a generic message
    # cannot be used to debug a statement.
    syntax = _refusal(call(sql="SELEKT 1"))
    assert _code(syntax) == "DatabaseErrorException", (
        f"a SQL syntax error must be DatabaseErrorException; got {_code(syntax)!r}: "
        f"{_message(syntax)!r}"
    )
    assert syntax.response["Error"]["Message"] == (
        'ERROR: syntax error at or near "SELEKT"; Position: 1; SQLState: 42601'
    ), (
        f"the engine's own wording (naming the offending token), its character position and its "
        f"syntax-error SQLSTATE must be passed through; got {_message(syntax)!r}"
    )

    # --- (7) Two request-shape refusals that never reach the engine at all.
    multi = _refusal(call(sql="SELECT 1; SELECT 2"))
    codes["multistatement"] = _code(multi)
    assert _code(multi) == "ValidationException", (
        f"two statements in one sql string must be refused with ValidationException; got "
        f"{_code(multi)!r}: {_message(multi)!r}"
    )
    assert multi.response["Error"]["Message"] == "Multistatements aren't supported.", (
        f"the multistatement refusal must be its own message; got {_message(multi)!r}"
    )

    schema_arg = _refusal(call(schema="public"))
    assert _code(schema_arg) == "ValidationException", (
        f"the modelled `schema` member is refused outright by the service; got "
        f"{_code(schema_arg)!r}: {_message(schema_arg)!r}"
    )
    assert schema_arg.response["Error"]["Message"] == "The schema parameter isn't supported.", (
        f"com.amazonaws.rdsdata#ExecuteStatement declares `schema` with no deprecation, and the "
        f"service refuses every request carrying it — a model-driven emulator honours it "
        f"instead. Got {_message(schema_arg)!r}"
    )

    # --- (8) Precedence again, the other way round: an empty sql beats the resource error, so
    # SQL validation runs BEFORE the cluster is resolved.
    empty_sql = _refusal(call(resourceArn=absent_cluster, sql=""))
    assert _code(empty_sql) == "ValidationException", (
        f"an empty sql must be refused with ValidationException even when the cluster is also "
        f"bad; got {_code(empty_sql)!r}: {_message(empty_sql)!r}"
    )
    assert empty_sql.response["Error"]["Message"] == "SQL is empty", (
        f"SQL validation must PRE-EMPT resource resolution, so the answer is the SQL error and "
        f"not {_message(bad_cluster)!r}; got {_message(empty_sql)!r}"
    )

    # --- (9) The taxonomy is genuinely a taxonomy: four distinct codes over one statement whose
    # only difference is which field was broken. An emulator answering one code for all of them
    # passes each envelope on its own and fails here.
    distinct = sorted(set(codes.values()))
    assert distinct == ["DatabaseErrorException", "HttpEndpointNotEnabledException",
                        "SecretsErrorException", "ValidationException"], (
        f"breaking the cluster, the cluster ARN's syntax, the secret, the database and the "
        f"statement shape must produce FOUR distinct modelled codes; got {codes!r}"
    )

    # --- (10) Effect absent: none of the nine refused calls changed anything.
    assert row_count() == 1, (
        f"no refused statement may have written to the control table; count is {row_count()}"
    )

@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Nine single-fault copies of a working ExecuteStatement fail with four pairwise distinct
    codes, pass the engine's SQLSTATE and wording through, report an empty sql before a bad
    cluster and a bad cluster before a bad secret, and leave the control table unchanged."""
    rds = ctx.client("rds")
    data = ctx.client("rds-data")
    resource_arn, secret_arn = _provision_data_api_cluster(ctx, rds, data)
    # Taken from the provisioned cluster's own ARN rather than from GetCallerIdentity: the two
    # bogus ARNs below must sit in the same account and region as the real one for the refusals
    # to be about the resource and not about ownership.
    _, _, _, arn_region, arn_account, _, _ = resource_arn.split(":", 6)
    _grade(data, resource_arn, secret_arn, arn_region, arn_account)


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
