"""redshift-spectrum-external-table-returns-rows-from-s3-without-loading-them."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redshift-spectrum-external-table-returns-rows-from-s3-without-loading-them"
GROUP = 'sql-data-plane'
SERVICES = ['redshift']


# ===== helpers =====

_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)

# Marks a data-plane failure, so "the control plane accepted the query and the engine returned
# nothing" is graded as a fidelity failure rather than an environment error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _wait_until(probe, done, timeout_s, interval_s, what="condition"):
    """Poll *probe* until *done*; never a bare sleep as the assertion."""
    deadline = time.monotonic() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed={observed!r}"
            )
        time.sleep(interval_s)


# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")
ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"
DB_NAME = "devdb"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
# Teardown has 1800 s in all: the DROP SCHEMA teardown before it takes up to 120 s and the role and
# bucket deletes after it need a margin, so the cluster delete and its wait for ClusterNotFound
# take what is left.
_DELETE_CLUSTER_DEADLINE_S = 1500
# A single-node cluster reaches `available` in ~60-90 s; the generous bounded deadline still
# FAILS rather than hanging.
_CLUSTER_DEADLINE_S = 900
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
# The first Data API statement against a freshly-available cluster includes connection
# establishment, so the statement deadline is deliberately larger than a warm query's.
_STATEMENT_DEADLINE_S = 420

_REDSHIFT_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "redshift.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _node_type(rs, cluster_type="single-node"):
    """Cheapest orderable node type for *cluster_type* in this region."""
    available = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = _retrying(lambda: rs.describe_orderable_cluster_options(**kwargs))
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != cluster_type:
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((nt for nt in NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type} options in this region")
        chosen = sorted(available)[0]
    return chosen


def _cluster_params(rs, cluster_id, **overrides):
    """Cheapest shape that still proves the invariant: ONE small node, not publicly
    accessible (the Data API reaches the cluster over the AWS-managed path), 1-day snapshot
    retention (RA3 refuses 0)."""
    params = dict(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(rs),
        MasterUsername=ADMIN_USERNAME,
        MasterUserPassword=ADMIN_PASSWORD,
        ClusterType="single-node",
        DBName=DB_NAME,
        PubliclyAccessible=False,
        Encrypted=True,
        AutomatedSnapshotRetentionPeriod=1,
    )
    params.update(overrides)
    return params


def _create_cluster(rs, cluster_id, **overrides):
    """CreateCluster with a bounded retry on the IAM-role races: a role created seconds ago is
    not yet visible to the Redshift control plane, which rejects the association outright rather
    than converging."""
    deadline = time.monotonic() + 180
    while True:
        try:
            return _retrying(lambda: rs.create_cluster(**_cluster_params(rs, cluster_id,
                                                                        **overrides)))
        except ClientError as exc:
            if _code_of(exc) not in ("InvalidIamRoleFault", "InvalidClusterState",
                                     "AccessDenied") or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _cluster_status(rs, cluster_id):
    try:
        resp = _retrying(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_CLUSTER:
            return None
        raise
    clusters = resp.get("Clusters", [])
    return clusters[0]["ClusterStatus"] if clusters else None


def _wait_for_cluster_available(rs, cluster_id, timeout_s=_CLUSTER_DEADLINE_S):
    terminal = {
        "available",
        "incompatible-network",
        "incompatible-parameters",
        "incompatible-hsm",
        "insufficient-capacity",
        "hardware-failure",
        None,
    }
    status = _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s in terminal,
        timeout_s=timeout_s,
        interval_s=15,
        what=f"cluster {cluster_id} to reach a terminal creation state",
    )
    assert status == "available", (
        f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'"
    )
    return status


def _delete_cluster(rs, cluster_id):
    """Cost-leak teardown. SkipFinalClusterSnapshot=True so no snapshot blocks the delete and
    none is left billing; a cluster still 'creating' refuses deletion, so that is retried, and the
    delete is asynchronous, so the wait for ClusterNotFound follows. One deadline bounds both."""
    deadline = time.monotonic() + _DELETE_CLUSTER_DEADLINE_S
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            if _code_of(exc) != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    _wait_cluster_gone(rs, cluster_id, deadline)


def _wait_cluster_gone(rs, cluster_id, deadline):
    """Poll DescribeClusters every 2 s until it answers ClusterNotFound; raise at *deadline*."""
    while True:
        try:
            clusters = rs.describe_clusters(ClusterIdentifier=cluster_id).get("Clusters", [])
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            raise
        if time.monotonic() >= deadline:
            status = clusters[0].get("ClusterStatus") if clusters else None
            raise TimeoutError(f"cluster {cluster_id} still listed ({status!r}) at the teardown "
                               f"deadline")
        time.sleep(2)


def _wait_statement(rsd, statement_id, timeout_s=_STATEMENT_DEADLINE_S):
    """Poll DescribeStatement to a TERMINAL status (SUBMITTED/PICKED/STARTED are transient)."""
    return _wait_until(
        lambda: _retrying(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s,
        interval_s=5,
        what=f"statement {statement_id} to reach a terminal status",
    )


def _submit(rsd, cluster_id, sql):
    return _retrying(lambda: rsd.execute_statement(
        ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=ADMIN_USERNAME, Sql=sql))["Id"]


def _describe_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S):
    """Submit *sql*, wait for terminal, return the DescribeStatement WITHOUT asserting."""
    return _wait_statement(rsd, _submit(rsd, cluster_id, sql), timeout_s=timeout_s)


def _run_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S):
    """Submit *sql*, wait for terminal, assert it FINISHED. Returns the statement id."""
    statement_id = _submit(rsd, cluster_id, sql)
    described = _wait_statement(rsd, statement_id, timeout_s=timeout_s)
    assert described["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: SQL {sql!r} did not FINISH: status={described['Status']!r} "
        f"error={described.get('Error')!r}"
    )
    return statement_id


def _select(rsd, cluster_id, sql):
    """Every row of a SELECT's result, paginated (GetStatementResult is token-paged)."""
    statement_id = _run_sql(rsd, cluster_id, sql)
    records, token = [], None
    while True:
        kwargs = {"Id": statement_id}
        if token:
            kwargs["NextToken"] = token
        resp = _retrying(lambda: rsd.get_statement_result(**kwargs))
        records.extend(resp.get("Records", []))
        token = resp.get("NextToken")
        if not token:
            break
    return records


def _cell(record, i):
    """The single scalar out of a Data API Field union cell, whatever member it used."""
    field = record[i]
    if field.get("isNull"):
        return None
    return next(iter(field.values()))


def _create_role(iam, name, policy, scenario):
    """A role Redshift can assume, with one inline policy, tagged at create."""
    arn = _retrying(lambda: iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_REDSHIFT_TRUST,
        Description=f"sim2real-behav redshift {scenario}",
        Tags=[{"Key": "sim2real", "Value": scenario}],
    ))["Role"]["Arn"]
    _retrying(lambda: iam.put_role_policy(
        RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(policy)))
    return arn


def _delete_role(iam, name):
    """A role holding an inline policy cannot be deleted, so drop the policies first."""
    try:
        for policy_name in _retrying(
                lambda: iam.list_role_policies(RoleName=name)).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=name, PolicyName=policy_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_bucket(s3, region, name, scenario):
    kwargs = {"Bucket": name}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    _retrying(lambda: s3.create_bucket(**kwargs))
    _retrying(lambda: s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": scenario}]}))
    return name


def _delete_bucket(s3, name):
    """Fully paginated empty-then-delete: a bucket holding one object refuses deletion."""
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objects:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_glue_database(glue, name):
    """CREATE EXTERNAL DATABASE creates a real Glue database that outlives the cluster, so it has
    its own teardown rather than relying on the cluster delete."""
    try:
        glue.delete_database(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


_PREFIX = "sim2real-behav/spectrum/"
# 20 rows; every third one from the first is 'keep', which is 7 of them.
_ROWS = [(i, "keep" if i % 3 == 1 else "skip") for i in range(1, 21)]
_KEPT = [(i, g) for i, g in _ROWS if g == "keep"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Spectrum SELECT over an external table on a known S3 CSV returns exactly the matching rows,
    the table is in svv_external_tables, and nothing is materialised in svv_table_info."""
    # Reference: https://docs.aws.amazon.com/redshift/latest/dg/c-using-spectrum.html
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    glue = ctx.client("glue")

    scenario = "rs-spectrum"
    bucket = ctx.unique_name("sim2real-behav-rs-spectrum-")
    # Registered BEFORE the create it undoes, so a failure between the two cannot leak.
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    _create_bucket(s3, ctx.region, bucket, scenario)

    key = _PREFIX + "rows.csv"
    body = "\n".join(f"{i},{g}" for i, g in _ROWS) + "\n"
    _retrying(lambda: s3.put_object(Bucket=bucket, Key=key, Body=body.encode(),
                                    Tagging="sim2real=" + scenario))

    role_name = ctx.unique_name("sim2real-behav-rs-spectrum-role-")
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    role_arn = _create_role(iam, role_name, {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"],
             "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
             "Resource": f"arn:aws:s3:::{bucket}"},
            # Spectrum's catalog side: the cluster creates and reads the Glue database and table
            # under this role, so the two halves must be in one policy.
            {"Effect": "Allow", "Action": ["glue:*"], "Resource": "*"},
        ],
    }, scenario)

    cluster_id = ctx.unique_name("sim2real-behav-rs-spectrum-")
    # A provisioned Redshift cluster is the single most expensive leak in this service, so this is
    # registered before the identifier is used anywhere.
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    _create_cluster(rs, cluster_id, IamRoles=[role_arn],
                    Tags=[{"Key": "sim2real", "Value": scenario}])
    _wait_for_cluster_available(rs, cluster_id)

    ident = ctx.unique_name("")[:10]
    schema = f"sim2real_behav_spectrum_{ident}"
    glue_db = f"sim2real_behav_rs_spectrum_{ident}"
    table = "sim2real_behav_ext"

    # The external schema CREATEs the Glue database, so its teardown is registered here -- before
    # the statement that creates it -- and DROP SCHEMA is registered after, so LIFO runs the SQL
    # drop first and the catalog delete second.
    ctx.on_cleanup(lambda: _delete_glue_database(glue, glue_db))
    ctx.on_cleanup(lambda: _describe_sql(rsd, cluster_id, f"DROP SCHEMA IF EXISTS {schema}",
                                         timeout_s=120))
    _run_sql(rsd, cluster_id,
             f"CREATE EXTERNAL SCHEMA {schema} FROM DATA CATALOG DATABASE '{glue_db}' "
             f"IAM_ROLE '{role_arn}' CREATE EXTERNAL DATABASE IF NOT EXISTS")

    _run_sql(rsd, cluster_id,
             f"CREATE EXTERNAL TABLE {schema}.{table} (id INT, grp VARCHAR(16)) "
             f"ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
             f"LOCATION 's3://{bucket}/{_PREFIX}'")

    # The Glue catalog really holds the definition the cluster just created, pointing at the
    # unmodified prefix rather than at a copy.
    catalogued = _retrying(lambda: glue.get_table(DatabaseName=glue_db, Name=table))["Table"]
    location = catalogued["StorageDescriptor"]["Location"]
    assert location.rstrip("/") == f"s3://{bucket}/{_PREFIX}".rstrip("/"), (
        f"the Glue table must point at the original S3 prefix, got {location!r}"
    )

    rows = _select(rsd, cluster_id,
                   f"SELECT id, grp FROM {schema}.{table} WHERE grp = 'keep' ORDER BY id")
    observed = [(_cell(r, 0), _cell(r, 1)) for r in rows]
    assert observed == _KEPT, (
        f"{DATAPLANE_MARKER}: the filtered projection must be exactly the matching lines of the "
        f"S3 object; got {observed!r} != {_KEPT!r}"
    )
    assert len(observed) == 7, (
        f"the CSV holds exactly 7 'keep' rows out of 20, got {len(observed)}"
    )

    external = _select(rsd, cluster_id,
                       "SELECT schemaname, tablename FROM svv_external_tables "
                       f"WHERE schemaname = '{schema}'")
    assert [(_cell(r, 0), _cell(r, 1)) for r in external] == [(schema, table)], (
        f"svv_external_tables must list exactly the external table just created, got "
        f"{external!r}"
    )

    # Effect absent, and the strongest assertion in the file: Spectrum read S3 in place, so the
    # table has NO local storage and therefore no svv_table_info row.
    local = _select(rsd, cluster_id,
                    'SELECT "schema", "table" FROM svv_table_info '
                    f"""WHERE "table" = '{table}'""")
    assert local == [], (
        f"an external table is read in place and must have no local storage, but svv_table_info "
        f"reports {local!r} — the rows were materialised into the cluster"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
