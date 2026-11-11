"""self-join-duplicate-column-names-refused-under-json-but-aliasing-one-side-succeeds."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "self-join-duplicate-column-names-refused-under-json-but-aliasing-one-side-succeeds"
GROUP = "negative-classes"
SERVICES = ["rds", "rds-data"]

_DB = "simparitydb"
_USER = "sim2real"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_MEMBER_WAIT_S = 1200
_CLUSTER_WAIT_S = 600
_TEARDOWN_WAIT_S = 900

# The duplicate-column-name refusal under formatRecordsAs=JSON, exactly as real AWS answers it.
_DUP_JSON = (
    "UnsupportedResultException",
    "The result can't be converted to JSON because it has a duplicate column.",
)


def _poll(fn, pred, *, timeout_s, interval_s=10):
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


def _delete_instance(rds, inst_id, timeout_s):
    """Delete a cluster member, retrying while it is in a non-deletable state, and wait for it
    to vanish."""
    deadline = time.monotonic() + timeout_s
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
                raise
            time.sleep(5)
    left = _poll(lambda: _instance(rds, inst_id), lambda i: i is None, timeout_s=timeout_s)
    assert left is None, (
        f"cluster member {inst_id} still exists {timeout_s}s after DeleteDBInstance; status "
        f"{left.get('DBInstanceStatus')!r}"
    )


def _delete_cluster(rds, cl_id, timeout_s):
    """Delete the cluster with no final snapshot, retrying while the member drains, then wait
    for it to vanish; the managed admin-user secret is deleted with the cluster."""
    deadline = time.monotonic() + timeout_s
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
                raise
            time.sleep(5)
    left = _poll(lambda: _cluster(rds, cl_id), lambda c: c is None, timeout_s=timeout_s)
    assert left is None, (
        f"cluster {cl_id} still exists {timeout_s}s after DeleteDBCluster; status "
        f"{left.get('Status')!r}"
    )


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=600.0, interval_s=5.0):
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


def _wait_data_api_ready(rds_data, resource_arn, secret_arn, timeout_s=300):
    """Poll ExecuteStatement until the Data API answers, tolerating the warm-up codes it raises
    while the proxy and the writer are not yet ready."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            rds_data.execute_statement(
                resourceArn=resource_arn, secretArn=secret_arn, database=_DB, sql="SELECT 1"
            )
            return
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code in (
                "DatabaseResumingException",
                "HttpEndpointNotEnabledException",
                "DatabaseNotFoundException",
                "ServiceUnavailableError",
                "DatabaseUnavailableException",
            ):
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"Data API never became ready (last error: {last_code})")


def _provision_cluster(ctx, rds, rds_data):
    """An aurora-postgresql Serverless v2 cluster with the Data API and an RDS-managed secret,
    its own teardown registered as soon as each piece exists. Returns (resource_arn, secret_arn)."""
    versions = rds.describe_db_engine_versions(
        Engine="aurora-postgresql", DefaultOnly=True
    ).get("DBEngineVersions", [])
    assert versions, (
        f"no aurora-postgresql engine version is orderable in {ctx.region!r} — the Data API "
        f"cannot be exercised here"
    )
    version = versions[0]["EngineVersion"]

    subnet_group = _network_db_subnet_group(ctx, rds)
    cl_id = ctx.unique_name("sim2real-behav-sjc-")
    rds.create_db_cluster(
        DBClusterIdentifier=cl_id,
        Engine="aurora-postgresql",
        EngineVersion=version,
        MasterUsername=_USER,
        ManageMasterUserPassword=True,
        DatabaseName=_DB,
        EnableHttpEndpoint=True,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 2.0},
        BackupRetentionPeriod=1,
        DeletionProtection=False,
        DBSubnetGroupName=subnet_group,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_cluster(rds, cl_id, _TEARDOWN_WAIT_S))

    member_id = ctx.unique_name("sim2real-behav-sjw-")
    rds.create_db_instance(
        DBInstanceIdentifier=member_id,
        DBClusterIdentifier=cl_id,
        Engine="aurora-postgresql",
        DBInstanceClass="db.serverless",
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, member_id, _TEARDOWN_WAIT_S))

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
        lambda c: c is not None and c.get("Status") == "available" and "MasterUserSecret" in c,
        timeout_s=_CLUSTER_WAIT_S,
    )
    assert cluster is not None and cluster.get("Status") == "available", (
        f"cluster {cl_id} did not reach 'available'; last status {(cluster or {}).get('Status')!r}"
    )
    resource_arn = cluster["DBClusterArn"]
    secret_arn = cluster["MasterUserSecret"]["SecretArn"]
    _wait_data_api_ready(rds_data, resource_arn, secret_arn)
    return resource_arn, secret_arn


def expect_error(fn, code, message):
    """Call fn(); assert it was refused with exactly (code, message). An unexpected SUCCESS
    raises, since a target accepting a call real AWS refuses is the strongest signal here."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, (
            f"expected {code!r}, got {err.get('Code')!r}: {err.get('Message')!r}"
        )
        assert err.get("Message") == message, (
            f"expected message {message!r}, got {err.get('Message')!r}"
        )
        return
    raise AssertionError(
        f"expected the call to be refused with {code!r}, but it succeeded: {result!r}"
    )


def _grade(ctx, data, resource_arn, secret_arn):
    table = ctx.unique_name("sim2real_behav_selfjoin_").replace("-", "_")

    def ex(sql, **kw):
        return data.execute_statement(
            resourceArn=resource_arn, secretArn=secret_arn, database=_DB, sql=sql, **kw
        )

    ex(f"CREATE TABLE {table} (id serial PRIMARY KEY)")
    ctx.on_cleanup(lambda: ex(f"DROP TABLE IF EXISTS {table}"))
    ex(f"INSERT INTO {table} DEFAULT VALUES")
    ex(f"INSERT INTO {table} DEFAULT VALUES")

    dup_sql = f"SELECT a.id, b.id FROM {table} a JOIN {table} b ON a.id = b.id"
    expect_error(lambda: ex(dup_sql, formatRecordsAs="JSON"), *_DUP_JSON)

    aliased_sql = f"SELECT a.id, b.id AS b_id FROM {table} a JOIN {table} b ON a.id = b.id"
    aliased = ex(aliased_sql, formatRecordsAs="JSON")
    rows = json.loads(aliased["formattedRecords"])
    assert sorted((r["id"], r["b_id"]) for r in rows) == [(1, 1), (2, 2)], (
        f"aliasing one side's column must remove the duplicate name and let formatRecordsAs="
        f"JSON succeed for the same self-join; expected [(1, 1), (2, 2)], got "
        f"{sorted((r['id'], r['b_id']) for r in rows)!r}"
    )


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A self-join selecting the same column name from both sides is refused under
    formatRecordsAs=JSON with a duplicate-key error, while aliasing one side's column makes the
    identical self-join succeed.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/data-api-json.html
    """
    rds = ctx.client("rds")
    data = ctx.client("rds-data")
    resource_arn, secret_arn = _provision_cluster(ctx, rds, data)
    _grade(ctx, data, resource_arn, secret_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
