"""continue-after-timeout-preserves-ddl-past-the-call-timeout."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "continue-after-timeout-preserves-ddl-past-the-call-timeout"
GROUP = "data-plane"
SERVICES = ["rds-data"]

_DB = "simparitydb"
_USER = "sim2real"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

# Provisioning ceilings, kept tight so their sum stays within the whole-check time budget.
_MEMBER_WAIT_S = 900
_CLUSTER_WAIT_S = 240
_SECRET_WAIT_S = 180
_DATA_API_WAIT_S = 180
# One deadline for the member, cluster and subnet-group deletes, inside the 1800 s cleanup budget.
_TEARDOWN_S = 1740

# The slow statement's own runtime. Must be comfortably longer than the documented 45 s call limit,
# because _TIMEOUT_UPPER_S < _SLOW_SQL_S is what proves the API cut the call off rather than waiting
# for the statement to finish.
_SLOW_SQL_S = 120
# Brackets around the documented 45 s cut-off, with margin for TLS and client retries.
_TIMEOUT_LOWER_S = 30
_TIMEOUT_UPPER_S = 80
# How long after the refusal leg B's table may take to appear. Its statement still has
# ~(_SLOW_SQL_S - 45) s to run when the call fails; this is that plus a wide margin.
_EFFECT_WAIT_S = 180

_CONTROL_TABLE = "sim2real_behav_cat_control"
_CANCELLED_TABLE = "sim2real_behav_cat_cancelled"
_CONTINUED_TABLE = "sim2real_behav_cat_continued"


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
    """DescribeDBInstances for one id, or None when it does not exist."""
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
            return None
        raise


def _cluster(rds, cl_id):
    """DescribeDBClusters for one id, or None when it does not exist."""
    try:
        return rds.describe_db_clusters(DBClusterIdentifier=cl_id)["DBClusters"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBClusterNotFoundFault":
            return None
        raise


def _teardown_deadline(teardown):
    """The run's one teardown deadline, started by the first delete."""
    if "deadline" not in teardown:
        teardown["deadline"] = time.monotonic() + _TEARDOWN_S
    return teardown["deadline"]


def _retry_busy(call, busy_code, gone_code, deadline) -> bool:
    """Call ``call``, retrying every 2 s while it answers ``busy_code``; False if already gone."""
    while True:
        try:
            call()
            return True
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == gone_code:
                return False
            if code != busy_code or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_instance(rds, inst_id, teardown):
    """Delete a cluster member and wait for it to vanish; a cluster cannot be deleted while a
    member remains."""
    deadline = _teardown_deadline(teardown)
    _retry_busy(lambda: rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True),
                "InvalidDBInstanceState", "DBInstanceNotFound", deadline)
    left = _poll(lambda: _instance(rds, inst_id), lambda i: i is None,
                 timeout_s=max(0.0, deadline - time.monotonic()), interval_s=2)
    if left is not None:
        raise RuntimeError(f"cluster member {inst_id} still exists at the teardown deadline")


def _delete_cluster(rds, cl_id, teardown):
    """Delete the cluster with no final snapshot, retrying while the member drains, and wait for
    it to vanish so its subnet group is released; the managed admin-user secret goes with it."""
    deadline = _teardown_deadline(teardown)
    _retry_busy(lambda: rds.delete_db_cluster(DBClusterIdentifier=cl_id, SkipFinalSnapshot=True),
                "InvalidDBClusterStateFault", "DBClusterNotFoundFault", deadline)
    left = _poll(lambda: _cluster(rds, cl_id), lambda c: c is None,
                 timeout_s=max(0.0, deadline - time.monotonic()), interval_s=2)
    if left is not None:
        raise RuntimeError(f"cluster {cl_id} still exists at the teardown deadline")


def _provision_data_api_cluster(ctx, rds, data):
    """Provision an aurora-postgresql Serverless v2 cluster with the Data API enabled.

    Returns (cluster_arn, secret_arn); RDS-managed credentials keep the password out of the file.
    """
    versions = rds.describe_db_engine_versions(
        Engine="aurora-postgresql", DefaultOnly=True
    ).get("DBEngineVersions", [])
    assert versions, (
        "no aurora-postgresql engine version is orderable in "
        f"{ctx.region!r} — the Data API cannot be exercised here"
    )
    version = versions[0]["EngineVersion"]

    cl_id = ctx.unique_name("sim2real-behav-cat-")
    teardown = {}
    subnet_group = _network_db_subnet_group(ctx, rds, teardown)
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
    ctx.on_cleanup(lambda: _delete_cluster(rds, cl_id, teardown))

    member_id = ctx.unique_name("sim2real-behav-caw-")
    rds.create_db_instance(
        DBInstanceIdentifier=member_id,
        DBClusterIdentifier=cl_id,
        Engine="aurora-postgresql",
        DBInstanceClass="db.serverless",
        Tags=_MANAGED_TAGS,
    )
    # Registered LAST -> torn down FIRST, before the cluster.
    ctx.on_cleanup(lambda: _delete_instance(rds, member_id, teardown))

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
        f"cluster {cl_id} did not reach 'available' within {_CLUSTER_WAIT_S}s; last "
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
        lambda: ((_cluster(rds, cl_id) or {}).get("MasterUserSecret") or {}).get("SecretStatus"),
        lambda s: s == "active",
        timeout_s=_SECRET_WAIT_S,
        interval_s=20,
    )
    assert secret_status == "active", (
        f"the managed MasterUserSecret must become 'active' within {_SECRET_WAIT_S}s; it is "
        f"{secret_status!r}"
    )

    cluster_arn = cluster["DBClusterArn"]
    # A cold Data API endpoint may refuse briefly after 'available'; any refusal is retried until
    # the deadline and then reported verbatim.
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
            time.sleep(10)
    assert warm is True, (
        f"the Data API never accepted a trivial statement on {cluster_arn} within "
        f"{_DATA_API_WAIT_S}s; the last refusal was {warm!r}"
    )
    return cluster_arn, secret_arn


def _refusal(fn):
    """Return the ClientError fn() raised; raise AssertionError if the call succeeded."""
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


def _slow_ddl(table: str) -> str:
    """A CTAS whose completion is delayed past the Data API's call limit by a pg_sleep subquery;
    the table's existence is the observable."""
    return f"CREATE TABLE {table} AS SELECT 1 AS id FROM (SELECT pg_sleep({_SLOW_SQL_S})) s"


def _grade(data, resource_arn, secret_arn) -> None:

    def ex(sql, **kw):
        return data.execute_statement(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB, sql=sql, **kw)

    def present() -> set:
        """Which of this check's three tables exist now, read independently through pg_catalog."""
        names = ", ".join(f"'{t}'" for t in
                          (_CONTROL_TABLE, _CANCELLED_TABLE, _CONTINUED_TABLE))
        rows = ex(
            "SELECT tablename FROM pg_catalog.pg_tables "
            f"WHERE schemaname = 'public' AND tablename IN ({names}) ORDER BY tablename"
        ).get("records") or []
        out = set()
        for row in rows:
            assert "stringValue" in row[0], (
                f"pg_tables.tablename must be returned in the stringValue arm; got {row[0]!r}"
            )
            out.add(row[0]["stringValue"])
        return out

    # Positive control: a fast DDL is visible through the same reflection query the absence legs
    # use, so "the table is absent" cannot mean "tables cannot be created or read at all".
    ex(f"CREATE TABLE {_CONTROL_TABLE} (id INT)")
    # One read, so the message reports the answer that failed.
    control_visible = present()
    assert control_visible == {_CONTROL_TABLE}, (
        f"positive control: a fast CREATE TABLE must be visible in pg_tables and must be the "
        f"ONLY one of this check's three tables present at this point; pg_tables reports "
        f"{sorted(control_visible)!r}"
    )

    # Leg A: continueAfterTimeout omitted, so the statement is cancelled at the call limit.
    started = time.monotonic()
    cancelled = _refusal(lambda: ex(_slow_ddl(_CANCELLED_TABLE)))
    elapsed_a = time.monotonic() - started
    assert _code(cancelled) == "StatementTimeoutException", (
        f"a statement that outruns the Data API's synchronous call limit must be refused with the "
        f"modelled StatementTimeoutException; got {_code(cancelled)!r}: {_message(cancelled)!r}"
    )
    # The default leg is cancelled by the engine, so the message is PostgreSQL's own.
    assert cancelled.response["Error"]["Message"] == "canceling statement due to statement timeout", (
        f"the default leg's StatementTimeoutException must carry the engine's cancellation "
        f"message; got {_message(cancelled)!r}"
    )
    # Two-sided clock: the lower bound rules out an instant rejection; the upper bound, below
    # _SLOW_SQL_S, proves the call was cut off rather than waited out.
    assert _TIMEOUT_LOWER_S <= elapsed_a <= _TIMEOUT_UPPER_S, (
        f"the refusal must arrive at the Data API's own call limit (documented 45 s), so between "
        f"{_TIMEOUT_LOWER_S}s and {_TIMEOUT_UPPER_S}s after the call — and strictly before the "
        f"{_SLOW_SQL_S}s statement could finish; it took {elapsed_a:.1f}s"
    )

    # Leg B: the same statement with continueAfterTimeout=True still fails the call; the flag only
    # stops the cancellation.
    started = time.monotonic()
    continued = _refusal(lambda: ex(_slow_ddl(_CONTINUED_TABLE), continueAfterTimeout=True))
    elapsed_b = time.monotonic() - started
    assert _code(continued) == _code(cancelled), (
        f"continueAfterTimeout must NOT change how the call ends — the caller still receives the "
        f"timeout error — so both legs must report the same code; the default leg said "
        f"{_code(cancelled)!r} and the continueAfterTimeout=True leg said {_code(continued)!r}"
    )
    # The statement is not cancelled, so the refusal is the API's own call timeout, not the
    # engine's cancellation.
    assert continued.response["Error"]["Message"] == "Request timed out", (
        f"the continueAfterTimeout=True leg's StatementTimeoutException must carry the Data "
        f"API's call-timeout message, not the engine's cancellation; got {_message(continued)!r}"
    )
    assert _TIMEOUT_LOWER_S <= elapsed_b <= _TIMEOUT_UPPER_S, (
        f"continueAfterTimeout=True must not extend the CALL either: the refusal must still "
        f"arrive between {_TIMEOUT_LOWER_S}s and {_TIMEOUT_UPPER_S}s, not after the {_SLOW_SQL_S}s "
        f"statement completes; it took {elapsed_b:.1f}s"
    )

    # Leg B's table must land, so a target ignoring the flag cannot pass on leg A's absence alone.
    landed = _poll(present, lambda names: _CONTINUED_TABLE in names,
                   timeout_s=_EFFECT_WAIT_S, interval_s=10)
    assert _CONTINUED_TABLE in landed, (
        f"continueAfterTimeout=True must leave the statement RUNNING after the call was refused, "
        f"so {_CONTINUED_TABLE!r} must appear in pg_tables within {_EFFECT_WAIT_S}s of the "
        f"refusal; pg_tables reports {sorted(landed)!r}"
    )
    # The CTAS selected exactly one row, so the completed statement must have written exactly one.
    rows = ex(f"SELECT id FROM {_CONTINUED_TABLE}").get("records") or []
    assert [r[0].get("longValue") for r in rows] == [1], (
        f"the continued CTAS must have finished its SELECT and written the one row it projected, "
        f"not merely created an empty table; {_CONTINUED_TABLE} holds {rows!r}"
    )

    # Leg A started earlier than leg B, whose table has landed, so leg A has had more time to land.
    # An exact set, so "nothing exists" cannot pass.
    final = present()
    assert final == {_CONTROL_TABLE, _CONTINUED_TABLE}, (
        f"with continueAfterTimeout at its default the cancelled statement must leave NO trace — "
        f"the documented behaviour is that 'the table isn't created' — while the control table "
        f"and the continueAfterTimeout=True table are both present. Expected exactly "
        f"{sorted({_CONTROL_TABLE, _CONTINUED_TABLE})!r}, got {sorted(final)!r}; "
        f"{_CANCELLED_TABLE!r} present means the flag does nothing and every timed-out DDL is "
        f"half-applied"
    )

    # Asserted last: dbConnectionId is @default 0 in the model, so a failure here means the member
    # is absent from the wire, not that the timeout contract is broken.
    for leg, exc in (("default", cancelled), ("continueAfterTimeout=True", continued)):
        conn = exc.response.get("dbConnectionId")
        assert isinstance(conn, int) and not isinstance(conn, bool), (
            f"StatementTimeoutException models a dbConnectionId (the connection that ran the "
            f"statement) and the {leg} leg must carry it as an integer; got {conn!r} from response "
            f"keys {sorted(k for k in exc.response if k != 'ResponseMetadata')!r}"
        )


# timing:real-time — lease: 45 s https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/data-api-timeouts.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A statement outrunning the Data API's 45 s call limit fails with StatementTimeoutException
    either way; by default its DDL never lands, with continueAfterTimeout=True it still lands.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/data-api-timeouts.html
    """
    rds = ctx.client("rds")
    data = ctx.client("rds-data")
    ctx.client("sts").get_caller_identity()
    resource_arn, secret_arn = _provision_data_api_cluster(ctx, rds, data)
    _grade(data, resource_arn, secret_arn)


def _network_db_subnet_group(ctx, client, teardown) -> str:
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
            teardown,
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, teardown, interval_s=2.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = _teardown_deadline(teardown)
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
