"""date-type-hint-rejects-unparseable-date-format."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "date-type-hint-rejects-unparseable-date-format"
GROUP = "representation"
SERVICES = ["rds", "rds-data"]

_DB = "simparitydb"
_USER = "sim2real"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_MEMBER_WAIT_S = 1200
_CLUSTER_WAIT_S = 600
_SECRET_WAIT_S = 300
_DATA_API_WAIT_S = 300
_TEARDOWN_WAIT_S = 900


# ===== shared helpers =====


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
    """Delete a cluster member, retrying while it is in a non-deletable state, and wait for it
    to vanish; a cluster with a remaining member cannot be deleted."""
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
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
            time.sleep(20)
    left = _poll(lambda: _instance(rds, inst_id), lambda i: i is None,
                 timeout_s=_TEARDOWN_WAIT_S, interval_s=20)
    assert left is None, (
        f"cluster member {inst_id} still exists {_TEARDOWN_WAIT_S}s after DeleteDBInstance; "
        f"status {left.get('DBInstanceStatus')!r}"
    )


def _delete_cluster(rds, cl_id):
    """Delete the cluster with no final snapshot, retrying while the member drains, then wait
    for it to vanish; the managed admin-user secret is deleted with the cluster."""
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
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
            time.sleep(20)
    left = _poll(lambda: _cluster(rds, cl_id), lambda c: c is None,
                 timeout_s=_TEARDOWN_WAIT_S, interval_s=20)
    assert left is None, (
        f"cluster {cl_id} still exists {_TEARDOWN_WAIT_S}s after DeleteDBCluster; status "
        f"{left.get('Status')!r}"
    )


def _teardown(rds, created):
    """Delete whatever _provision_data_api_cluster created, member first; the cluster delete is
    attempted even when the member delete fails, and the first failure is re-raised."""
    try:
        if "member" in created:
            _delete_instance(rds, created["member"])
    finally:
        if "cluster" in created:
            _delete_cluster(rds, created["cluster"])


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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
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
    ctx.on_cleanup(lambda: _delete_cluster(rds, cl_id))

    member_id = ctx.unique_name("sim2real-behav-rdw-")
    rds.create_db_instance(
        DBInstanceIdentifier=member_id,
        DBClusterIdentifier=cl_id,
        Engine="aurora-postgresql",
        DBInstanceClass="db.serverless",
        Tags=_MANAGED_TAGS,
    )
    created["member"] = member_id
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
        f"{cluster.get('HttpEndpointEnabled')!r}"
    )

    secret_arn = (cluster.get("MasterUserSecret") or {}).get("SecretArn")
    assert secret_arn, (
        "a cluster with a managed admin-user password must publish that secret's ARN; got "
        f"{cluster.get('MasterUserSecret')!r}"
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
        f"the managed admin-user secret must become 'active'; it is {secret_status!r}"
    )

    cluster_arn = cluster["DBClusterArn"]
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
    """The ClientError fn() raised; raises AssertionError if the call succeeded instead."""
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

_TABLE = "sim2real_behav_date_hint"

# Written with a DATE hint in the documented YYYY-MM-DD format, read back unchanged.
_VALID_DATE = "2026-10-22"

# Hint present, value unparseable in either of two shapes: a day/month/year date and an
# ISO-8601 date-time. Both are refused by the Data API itself before the engine sees anything,
# with no `ERROR:` prefix and no SQLState.
_ENGINE_CODE = "DatabaseErrorException"
_ENGINE_STATUS = 400
_UNPARSEABLE = [
    ("22/10/2026", "Parse Error for Date: input contains invalid characters"),
    ("2026-10-22T00:00", "Parse Error for Date: trailing input"),
]


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

    ex(f"CREATE TABLE {_TABLE} (id int PRIMARY KEY, d date)")

    # Positive control: the documented YYYY-MM-DD format is accepted and round-trips unchanged.
    control = ex(f"INSERT INTO {_TABLE} (id, d) VALUES (1, :p)",
                parameters=[param("p", {"stringValue": _VALID_DATE}, "DATE")])
    assert _envelope(control) == {"numberOfRecordsUpdated": 1, "generatedFields": []}, (
        f"the valid DATE write must be accepted as an ordinary single-row INSERT; got "
        f"{_envelope(control)!r}"
    )
    round_trip = ex(f"SELECT d FROM {_TABLE} WHERE id = 1")
    assert _envelope(round_trip) == {
        "records": [[{"stringValue": _VALID_DATE}]], "numberOfRecordsUpdated": 0,
    }, (
        f"a DATE hint in the accepted YYYY-MM-DD format must round-trip unchanged; got "
        f"{_envelope(round_trip)!r}"
    )

    for value, message in _UNPARSEABLE:
        _refused(
            _refusal(lambda v=value: ex(
                f"INSERT INTO {_TABLE} (id, d) VALUES (2, :p)",
                parameters=[param("p", {"stringValue": v}, "DATE")])),
            (_ENGINE_CODE, _ENGINE_STATUS, message),
            f"a DATE hint on the unparseable value {value!r}",
        )
        after = ids()
        assert after == [1], (
            f"a DATE hint on {value!r} must be refused with nothing written, so row 2 must be "
            f"absent; the table holds ids {after!r}"
        )

    # A further positive control: a second valid DATE write still succeeds after both refusals.
    ex(f"INSERT INTO {_TABLE} (id, d) VALUES (3, :p)",
       parameters=[param("p", {"stringValue": _VALID_DATE}, "DATE")])
    final = ids()
    assert final == [1, 3], (
        f"the account must still accept a valid DATE write after both unparseable refusals; "
        f"got ids {final!r}"
    )


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DATE-hinted parameter in the documented YYYY-MM-DD format round-trips unchanged; a
    DATE-hinted value in a different date or date-time format is refused by the Data API with
    nothing written.

    Reference: https://docs.aws.amazon.com/rdsdataservice/latest/APIReference/API_SqlParameter.html
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
        _teardown(rds, created)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
