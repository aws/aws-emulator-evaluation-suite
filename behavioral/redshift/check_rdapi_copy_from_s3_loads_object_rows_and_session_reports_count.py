"""rdapi-copy-from-s3-loads-object-rows-and-session-reports-count."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rdapi-copy-from-s3-loads-object-rows-and-session-reports-count"
GROUP = "bulk-load"
SERVICES = ["redshift"]

_TABLE = "sim2real_rdapi_copy"
_KEY = "sim2real-behav/good.csv"
_CSV = "1,alpha,10.50\n2,bravo,20.25\n3,charlie,30.75\n"
# DECIMAL(9,2) comes back as stringValue
# with the scale preserved, so a loader that rounds or reformats is visible here.
_EXPECTED_ROWS = [
    [{"longValue": 1}, {"stringValue": "alpha"}, {"stringValue": "10.50"}],
    [{"longValue": 2}, {"stringValue": "bravo"}, {"stringValue": "20.25"}],
    [{"longValue": 3}, {"stringValue": "charlie"}, {"stringValue": "30.75"}],
]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """COPY ingests from S3: three CSV rows land in the table with values and DECIMAL scale intact,
    the COPY reports no result set, and a COPY in a kept-alive session has its row count confirmed
    by pg_last_copy_count() in that same session."""
    rs_data = ctx.client("redshift-data")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    scenario = "rdapi-copy"

    bucket = ctx.unique_name("sim2real-behav-rdapi-copy-")
    # Registered BEFORE the create it undoes, so a failure between the two cannot leak.
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    _create_bucket(s3, ctx.region, bucket, scenario)
    _retrying(lambda: s3.put_object(Bucket=bucket, Key=_KEY, Body=_CSV.encode(),
                                    Tagging="sim2real=" + scenario))

    role_name = ctx.unique_name("sim2real-behav-rdapi-copy-role-")
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    role_arn = _create_copy_role(iam, role_name, bucket, scenario)

    cluster_id = _provision_cluster(ctx, scenario, iam_roles=[role_arn])
    attached = [r["IamRoleArn"] for r in _retrying(
        lambda: ctx.client("redshift").describe_clusters(
            ClusterIdentifier=cluster_id))["Clusters"][0]["IamRoles"]]
    assert attached == [role_arn], (
        f"the cluster must carry exactly the COPY role; got {attached!r} want {[role_arn]!r}")

    _run_sql(rs_data, cluster_id,
             f"CREATE TABLE {_TABLE} (id INT, name VARCHAR(32), amt DECIMAL(9,2))")

    copy_sql = (f"COPY {_TABLE} (id, name, amt) FROM 's3://{bucket}/{_KEY}' "
                f"IAM_ROLE '{role_arn}' CSV")
    copied = _describe_sql(rs_data, cluster_id, copy_sql)
    assert copied["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: COPY of three well-formed rows must FINISH, got "
        f"{copied['Status']!r} error={copied.get('Error')!r}")
    assert copied["HasResultSet"] is False, (
        f"a COPY returns no result set; got {copied.get('HasResultSet')!r}")
    assert copied["ResultRows"] == 0 and copied["ResultSize"] == 0, (
        f"a COPY reports ResultRows/ResultSize 0 -- the loaded count is NOT surfaced there; got "
        f"{copied.get('ResultRows')!r}/{copied.get('ResultSize')!r}")

    counted = _select(rs_data, cluster_id, f"SELECT count(*) FROM {_TABLE}")
    assert counted == [[{"longValue": 3}]], (
        f"{DATAPLANE_MARKER}: COPY must ingest exactly the three rows in the object; got "
        f"{counted!r}")
    loaded = _select(rs_data, cluster_id, f"SELECT id, name, amt FROM {_TABLE} ORDER BY id")
    assert loaded == _EXPECTED_ROWS, (
        f"the loaded rows must match the CSV after type conversion; got {loaded!r} want "
        f"{_EXPECTED_ROWS!r}")

    # The engine's own accounting of the load, which is SESSION-scoped: run a second COPY keeping
    # the session alive, then read pg_last_copy_count() in that same session.
    session_copy = _describe_sql(rs_data, cluster_id, copy_sql, SessionKeepAliveSeconds=180)
    assert session_copy["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: the second COPY must FINISH, got {session_copy['Status']!r} "
        f"error={session_copy.get('Error')!r}")
    session_id = session_copy.get("SessionId")
    assert session_id, (
        f"a statement run with SessionKeepAliveSeconds must report the SessionId it kept alive; "
        f"got {session_copy!r}")

    reuse_id = _submit_in_session(rs_data, session_id, "SELECT pg_last_copy_count()")
    reused = _wait_statement(rs_data, reuse_id)
    assert reused["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: the kept-alive session must still accept statements, got "
        f"{reused['Status']!r} error={reused.get('Error')!r}")
    reported, _ = _result(rs_data, reuse_id)
    assert reported == [[{"longValue": 3}]], (
        f"{DATAPLANE_MARKER}: pg_last_copy_count() in the COPY's own session must report the "
        f"three rows that COPY loaded; got {reported!r}")
    total = _select(rs_data, cluster_id, f"SELECT count(*) FROM {_TABLE}")
    assert total == [[{"longValue": 6}]], (
        f"the second COPY of the same object must append three more rows; got {total!r}")


def _submit_in_session(rsd, session_id, sql):
    """ExecuteStatement addressed at a live SESSION rather than at a cluster: the target is the
    session id alone, and passing a cluster alongside it is rejected."""
    return _retrying(lambda: rsd.execute_statement(SessionId=session_id, Sql=sql))["Id"]


# ===== helpers =====
# The node type is derived from DescribeOrderableClusterOptions: dc2.large is not orderable in
# every region, so a pinned type can fail CreateCluster with InvalidParameterValue.

_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded",
             "TooManyRequestsException", "SlowDown")
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
# Cheapest first; whatever this region actually offers for a single node wins.
_SINGLE_NODE_PREFERENCE = ("ra3.large", "rg.large", "ra3.xlplus")
MASTER_USERNAME = "adminuser"
MASTER_PASSWORD = "TestPassw0rd123"  # noqa: S105 - throwaway cluster deleted in teardown
DB_NAME = "devdb"
# A single-node cluster reaches `available` in minutes and a first statement in seconds;
# _wait_until returns the instant its condition holds, and a target that never converges FAILS.
_CLUSTER_DEADLINE_S = 1200
_STATEMENT_DEADLINE_S = 420

# Prefixes a failure in which the API accepted the SQL but the engine never ran it to completion.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying ONLY on API throttling: a rate limit under parallel pool use is
    infrastructure noise, never a behavioral observation."""
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
    """Poll *probe* until *done*; never a bare sleep standing in for the wait."""
    deadline = time.monotonic() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed={observed!r}")
        time.sleep(interval_s)


def _error(fn):
    """(code, HTTP status, message) of the ClientError *fn* raises.

    Raises when the call SUCCEEDS, so an accepted call is reported as such and not as something
    that reads like a naming difference."""
    try:
        fn()
    except ClientError as exc:
        return (exc.response["Error"]["Code"],
                exc.response["ResponseMetadata"]["HTTPStatusCode"],
                exc.response["Error"]["Message"])
    raise AssertionError("the call SUCCEEDED where real AWS rejects it")


def _node_type(rs):
    """Cheapest orderable SINGLE-NODE type in this region, fully paginated."""
    available, marker = [], None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = _retrying(lambda: rs.describe_orderable_cluster_options(**kwargs))
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") == "single-node" and opt.get("NodeType") not in available:
                available.append(opt["NodeType"])
        marker = resp.get("Marker")
        if not marker:
            break
    assert available, "no orderable single-node cluster options in this region"
    return next((n for n in _SINGLE_NODE_PREFERENCE if n in available), sorted(available)[0])


def _cluster_status(rs, cluster_id):
    try:
        resp = _retrying(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_CLUSTER:
            return None
        raise
    clusters = resp.get("Clusters", [])
    return clusters[0]["ClusterStatus"] if clusters else None


def _delete_cluster(rs, cluster_id):
    """Cost-leak teardown: SkipFinalClusterSnapshot so no snapshot blocks the delete and none is
    left billing. A cluster still `creating` refuses deletion, so retry inside a bounded window."""
    deadline = time.monotonic() + 600
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CLUSTER:
                return
            if _code_of(exc) != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _provision_cluster(ctx, scenario, iam_roles=()):
    """A fresh single-node cluster, teardown registered BEFORE the create, waited to `available`.

    No ClusterSubnetGroupName and PubliclyAccessible=False: the Data API reaches the cluster over
    the AWS-managed path, and without Enhanced VPC Routing so does COPY's S3 read, so this check
    needs no VPC of its own and never touches one.
    """
    rs = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-behav-rdapi-")
    # A provisioned Redshift cluster is the most expensive leak in this service, so teardown is
    # registered before the identifier is used anywhere at all.
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    params = dict(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(rs),
        MasterUsername=MASTER_USERNAME,
        MasterUserPassword=MASTER_PASSWORD,
        ClusterType="single-node",
        DBName=DB_NAME,
        PubliclyAccessible=False,
        Encrypted=True,
        AutomatedSnapshotRetentionPeriod=1,  # RA3 refuses 0
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )
    if iam_roles:
        # Attached AT CREATE rather than through ModifyClusterIamRoles: the association is then
        # complete when the cluster is, and the ~105 s provisioning wait doubles as the IAM
        # propagation window a COPY needs.
        params["IamRoles"] = list(iam_roles)
    deadline = time.monotonic() + 180
    while True:
        try:
            _retrying(lambda: rs.create_cluster(**params))
            break
        except ClientError as exc:
            # A role created seconds ago is not yet visible to the Redshift control plane, which
            # rejects the association outright rather than converging: the one place a create
            # legitimately retries on a 4xx.
            if _code_of(exc) not in ("InvalidIamRoleFault", "AccessDenied") \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    status = _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s in ("available", "incompatible-network", "incompatible-parameters",
                        "incompatible-hsm", "insufficient-capacity", "hardware-failure", None),
        timeout_s=_CLUSTER_DEADLINE_S, interval_s=10,
        what=f"cluster {cluster_id} to reach a terminal creation state")
    assert status == "available", (
        f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'")
    return cluster_id


def _submit(rsd, cluster_id, sql, **extra):
    return _retrying(lambda: rsd.execute_statement(
        ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=MASTER_USERNAME, Sql=sql,
        **extra))["Id"]


def _wait_statement(rsd, statement_id, timeout_s=_STATEMENT_DEADLINE_S):
    """Poll DescribeStatement to a TERMINAL status; SUBMITTED/PICKED/STARTED are transient."""
    return _wait_until(
        lambda: _retrying(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s, interval_s=3,
        what=f"statement {statement_id} to reach a terminal status")


def _describe_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S, **extra):
    """Submit *sql*, wait for terminal, return the DescribeStatement WITHOUT asserting on it."""
    return _wait_statement(rsd, _submit(rsd, cluster_id, sql, **extra), timeout_s=timeout_s)


def _run_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S, **extra):
    """Submit *sql*, wait for terminal, assert it FINISHED. -> the statement id."""
    statement_id = _submit(rsd, cluster_id, sql, **extra)
    described = _wait_statement(rsd, statement_id, timeout_s=timeout_s)
    assert described["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: SQL {sql!r} did not FINISH: status={described['Status']!r} "
        f"error={described.get('Error')!r}")
    return statement_id


def _result(rsd, statement_id):
    """(all records, the last page) of GetStatementResult, token-paginated."""
    records, token, page = [], None, None
    while True:
        kwargs = {"Id": statement_id}
        if token:
            kwargs["NextToken"] = token
        page = _retrying(lambda: rsd.get_statement_result(**kwargs))
        records.extend(page.get("Records", []))
        token = page.get("NextToken")
        if not token:
            return records, page


def _select(rsd, cluster_id, sql):
    """Every row of a SELECT that must FINISH."""
    return _result(rsd, _run_sql(rsd, cluster_id, sql))[0]


def _cell(record, i):
    """The single scalar out of a Data API Field union cell, whatever member it used."""
    field = record[i]
    if field.get("isNull"):
        return None
    return next(iter(field.values()))


_REDSHIFT_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "redshift.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _create_bucket(s3, region, name, scenario):
    kwargs = {"Bucket": name}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    _retrying(lambda: s3.create_bucket(**kwargs))
    _retrying(lambda: s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": scenario}]}))


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


def _create_copy_role(iam, name, bucket, scenario):
    """A role Redshift can assume to read exactly this bucket, tagged at create."""
    arn = _retrying(lambda: iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_REDSHIFT_TRUST,
        Description=f"sim2real-behav redshift {scenario}",
        Tags=[{"Key": "sim2real", "Value": scenario}]))["Role"]["Arn"]
    _retrying(lambda: iam.put_role_policy(
        RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject"],
                 "Resource": f"arn:aws:s3:::{bucket}/*"},
                {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                 "Resource": f"arn:aws:s3:::{bucket}"},
            ]})))
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
