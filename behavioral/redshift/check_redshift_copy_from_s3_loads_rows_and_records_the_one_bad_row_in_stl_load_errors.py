"""redshift-copy-from-s3-loads-rows-and-records-the-one-bad-row-in-stl-load-errors."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redshift-copy-from-s3-loads-rows-and-records-the-one-bad-row-in-stl-load-errors"
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

# Marks a data-plane failure: the control plane accepted the statement but the engine did
# not do the work.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
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
# Teardown has 1800 s in all: the DROP teardown before it takes up to 120 s and the role and bucket
# deletes after it need a margin, so the cluster delete and its wait for ClusterNotFound take what
# is left.
_DELETE_CLUSTER_DEADLINE_S = 1500
# A single-node dc2.large reaches `available` in ~60-90 s. The generous
# bounded deadline still FAILS rather than hanging, and _wait_until returns the instant the
# cluster is available, so a fast emulator pays nothing for the headroom.
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
    """Cheapest shape that still proves the invariant: ONE dc2.large node, not publicly
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
    """CreateCluster with a bounded retry on the IAM-role races.

    A role created seconds ago is not yet visible to the Redshift control plane, which rejects the
    association outright rather than converging — so this is the one place a create legitimately
    retries on a 4xx.
    """
    deadline = time.monotonic() + 180
    while True:
        try:
            return _retrying(lambda: rs.create_cluster(**_cluster_params(rs, cluster_id,
                                                                        **overrides)))
        except ClientError as exc:
            code = _code_of(exc)
            if code not in ("InvalidIamRoleFault", "InvalidClusterState",
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
    """A role Redshift can assume, with one inline policy, tagged at creation."""
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


_TABLE = "sim2real_behav_copy_stl"
# Nine well-formed rows and one whose `qty` is not an integer. The bad row is in the MIDDLE so a
# COPY that simply stopped at the first parse error would load 4 rows, not 9.
_GOOD_ROWS = [
    (1, "alpha", 10), (2, "bravo", 20), (3, "charlie", 30), (4, "delta", 40),
    (6, "foxtrot", 60), (7, "golf", 70), (8, "hotel", 80), (9, "india", 90),
    (10, "juliet", 100),
]
_BAD_LINE = "5,echo,not-a-number"


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """COPY from S3 loads the nine well-formed CSV rows with their values intact, rejects the
    tenth, and records that one rejection in stl_load_errors naming the column and raw value."""
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    scenario = "rs-copy-stl"
    bucket = ctx.unique_name("sim2real-behav-rs-copy-")
    # Registered BEFORE the create it undoes, so a failure between the two cannot leak.
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    _create_bucket(s3, ctx.region, bucket, scenario)

    key = "sim2real-behav/load.csv"
    csv_lines = [f"{i},{n},{q}" for i, n, q in _GOOD_ROWS[:4]] + [_BAD_LINE] + \
                [f"{i},{n},{q}" for i, n, q in _GOOD_ROWS[4:]]
    _retrying(lambda: s3.put_object(
        Bucket=bucket, Key=key, Body=("\n".join(csv_lines) + "\n").encode(),
        Tagging="sim2real=" + scenario))

    role_name = ctx.unique_name("sim2real-behav-rs-copy-role-")
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    role_arn = _create_role(iam, role_name, {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"],
             "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
             "Resource": f"arn:aws:s3:::{bucket}"},
        ],
    }, scenario)

    cluster_id = ctx.unique_name("sim2real-behav-rs-copy-")
    # A provisioned Redshift cluster is the single most expensive leak in this service, so this is
    # registered before the identifier is used anywhere.
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    # The role is attached AT CREATE rather than through ModifyClusterIamRoles: the association is
    # then complete when the cluster is, and the ~90 s provisioning wait doubles as the IAM
    # propagation window the COPY needs.
    _create_cluster(rs, cluster_id, IamRoles=[role_arn],
                    Tags=[{"Key": "sim2real", "Value": scenario}])
    _wait_for_cluster_available(rs, cluster_id)

    attached = [r["IamRoleArn"] for r in _retrying(
        lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))["Clusters"][0]["IamRoles"]]
    assert attached == [role_arn], (
        f"the cluster must carry exactly the COPY role, got {attached!r} want {[role_arn]!r}"
    )

    _run_sql(rsd, cluster_id,
             f"CREATE TABLE {_TABLE} (id INT, name VARCHAR(32), qty INT)")
    ctx.on_cleanup(lambda: _describe_sql(rsd, cluster_id, f"DROP TABLE IF EXISTS {_TABLE}",
                                         timeout_s=120))

    copy_sql = (
        f"COPY {_TABLE} (id, name, qty) FROM 's3://{bucket}/{key}' "
        f"IAM_ROLE '{role_arn}' CSV MAXERROR 2"
    )
    copy_status = _describe_sql(rsd, cluster_id, copy_sql)
    assert copy_status["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: COPY with one bad row and MAXERROR 2 must FINISH, got "
        f"{copy_status['Status']!r} error={copy_status.get('Error')!r}"
    )

    count = _select(rsd, cluster_id, f"SELECT count(*) FROM {_TABLE}")
    assert count == [[{"longValue": 9}]], (
        f"COPY must ingest the nine well-formed rows and reject the tenth, got {count!r}"
    )

    loaded = _select(rsd, cluster_id, f"SELECT id, name, qty FROM {_TABLE} ORDER BY id")
    expected = [[{"longValue": i}, {"stringValue": n}, {"longValue": q}]
                for i, n, q in _GOOD_ROWS]
    assert loaded == expected, (
        f"the loaded rows must match the CSV byte-for-byte after type conversion; got "
        f"{loaded!r} != {expected!r}"
    )

    # The cluster's own accounting of the rejection — the only observable for it anywhere.
    errors = _select(rsd, cluster_id,
                     "SELECT slice, btrim(colname), btrim(raw_field_value), btrim(err_reason), "
                     f"line_number FROM stl_load_errors WHERE filename LIKE '%{key}%' "
                     "ORDER BY slice")
    assert errors, (
        f"{DATAPLANE_MARKER}: the cluster rejected a row (only 9 of 10 loaded) but recorded "
        f"nothing in stl_load_errors for {key!r}"
    )
    # On real Redshift (single-node dc2.large) the ONE bad
    # line is reported once PER SLICE that scanned it — two identical rows on a 2-slice single
    # node. So the falsifiable claim is over the distinct rejection, plus the fact that the
    # duplication is per-slice and nothing else.
    rejections = {(_cell(r, 1), _cell(r, 2), _cell(r, 3), _cell(r, 4)) for r in errors}
    assert len(rejections) == 1, (
        f"exactly one line was malformed, so stl_load_errors must describe exactly one distinct "
        f"rejection; got {sorted(rejections)!r}"
    )
    assert len({_cell(r, 0) for r in errors}) == len(errors), (
        f"stl_load_errors repeats a rejection only across slices, so each of the {len(errors)} "
        f"rows must come from a different slice; got slices "
        f"{sorted(_cell(r, 0) for r in errors)!r}"
    )
    colname, raw_value, err_reason, line_number = next(iter(rejections))
    assert colname == "qty", (
        f"stl_load_errors must name the offending COLUMN, got {colname!r} in {errors[0]!r}"
    )
    assert raw_value == "not-a-number", (
        f"stl_load_errors must carry the offending RAW value, got {raw_value!r}"
    )
    assert err_reason == "Invalid digit, Value 'n', Pos 0, Type: Integer", (
        f"stl_load_errors must explain the integer parse failure, got {err_reason!r}"
    )
    assert line_number == 5, (
        f"stl_load_errors must name the offending line number 5, got {line_number!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
