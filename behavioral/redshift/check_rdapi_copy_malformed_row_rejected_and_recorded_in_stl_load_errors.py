"""rdapi-copy-malformed-row-rejected-and-recorded-in-stl-load-errors."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rdapi-copy-malformed-row-rejected-and-recorded-in-stl-load-errors"
GROUP = "bulk-load"
SERVICES = ["redshift"]

_TABLE = "sim2real_rdapi_copy_bad"
_KEY = "sim2real-behav/bad.csv"
# Three CSV rows, the MIDDLE one unparseable for a DECIMAL column. Must stay byte-identical,
# because err_reason quotes a character position in it.
_CSV = "1,alpha,10.50\n2,bravo,not-a-number\n3,charlie,30.75\n"
# Note the DOUBLE space after "failed." and that the message points at stl_load_errors rather
# than naming the bad value.
_EXPECTED_ERROR = (
    f"ERROR: Load into table '{_TABLE}' failed.  Check 'stl_load_errors' system table for details."
)
_EXPECTED_REJECTION = ("amt", "numeric", "not-a-number",
                       "Invalid exponent, Value 'r', Pos 11, Type: Decimal", 1207, 2)


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """One malformed row fails a default COPY, leaves the table empty, and is recorded once in
    stl_load_errors with column, type, value, reason, code and line; MAXERROR loads the good rows.

    Reference: https://docs.aws.amazon.com/redshift/latest/dg/r_STL_LOAD_ERRORS.html
    """
    rs_data = ctx.client("redshift-data")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    scenario = "rdapi-copy-bad"

    bucket = ctx.unique_name("sim2real-behav-rdapi-bad-")
    # Registered BEFORE the create it undoes, so a failure between the two cannot leak.
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    _create_bucket(s3, ctx.region, bucket, scenario)
    _retrying(lambda: s3.put_object(Bucket=bucket, Key=_KEY, Body=_CSV.encode(),
                                    Tagging="sim2real=" + scenario))

    role_name = ctx.unique_name("sim2real-behav-rdapi-bad-role-")
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    role_arn = _create_copy_role(iam, role_name, bucket, scenario)

    cluster_id = _provision_cluster(ctx, scenario, iam_roles=[role_arn])
    _run_sql(rs_data, cluster_id,
             f"CREATE TABLE {_TABLE} (id INT, name VARCHAR(32), amt DECIMAL(9,2))")

    # Break exactly one thing: one row of the object cannot be parsed into the declared column.
    copy_sql = (f"COPY {_TABLE} (id, name, amt) FROM 's3://{bucket}/{_KEY}' "
                f"IAM_ROLE '{role_arn}' CSV")
    failed = _describe_sql(rs_data, cluster_id, copy_sql)

    assert failed["Status"] == "FAILED", (
        f"the default error handling tolerates no bad row, so the COPY must land FAILED; got "
        f"{failed['Status']!r} error={failed.get('Error')!r}")
    assert failed.get("Error") == _EXPECTED_ERROR, (
        f"the async record must carry the engine's load-failure text naming the table and "
        f"stl_load_errors; got {failed.get('Error')!r} want {_EXPECTED_ERROR!r}")
    assert failed["HasResultSet"] is False, (
        f"a failed COPY has no result set; got {failed.get('HasResultSet')!r}")

    # The effect is absent: a failed load is all-or-nothing, NOT the two parseable rows.
    empty = _select(rs_data, cluster_id, f"SELECT count(*) FROM {_TABLE}")
    assert empty == [[{"longValue": 0}]], (
        f"a failed COPY must leave the table empty, not partially loaded; got {empty!r}")

    # The cluster's own accounting of the rejection -- the only observable for it anywhere. It
    # survives the load's rollback, which is the non-obvious half of the claim.
    errors = _select(rs_data, cluster_id,
                     "SELECT slice, btrim(colname), btrim(type), btrim(raw_field_value), "
                     "btrim(err_reason), err_code, line_number FROM stl_load_errors "
                     f"WHERE filename LIKE '%{_KEY}%' ORDER BY slice")
    assert errors, (
        f"{DATAPLANE_MARKER}: the cluster rejected a row but recorded nothing in "
        f"stl_load_errors for {_KEY!r}")
    # A rejection is reported once PER SLICE that scanned the line, so the falsifiable claim is
    # over the DISTINCT rejection plus the fact that any duplication is per-slice and nothing else.
    rejections = {tuple(_cell(r, i) for i in range(1, 7)) for r in errors}
    assert len(rejections) == 1, (
        f"exactly one line was malformed, so stl_load_errors must describe exactly one distinct "
        f"rejection; got {sorted(rejections)!r}")
    assert len({_cell(r, 0) for r in errors}) == len(errors), (
        f"stl_load_errors repeats a rejection only across slices, so each of the {len(errors)} "
        f"rows must come from a different slice; got slices "
        f"{sorted(_cell(r, 0) for r in errors)!r}")
    assert next(iter(rejections)) == _EXPECTED_REJECTION, (
        f"stl_load_errors must name the column, its type, the raw value, the parse reason, the "
        f"error code and the line number; got {next(iter(rejections))!r} want "
        f"{_EXPECTED_REJECTION!r}")

    # The positive control, on the same object and the same cluster: tolerate the one rejection
    # and the two well-formed rows do load.
    tolerated = _describe_sql(rs_data, cluster_id, copy_sql + " MAXERROR 2")
    assert tolerated["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: with MAXERROR past the single rejection the same COPY must FINISH; "
        f"got {tolerated['Status']!r} error={tolerated.get('Error')!r}")
    loaded = _select(rs_data, cluster_id, f"SELECT id, name FROM {_TABLE} ORDER BY id")
    assert loaded == [[{"longValue": 1}, {"stringValue": "alpha"}],
                      [{"longValue": 3}, {"stringValue": "charlie"}]], (
        f"{DATAPLANE_MARKER}: the tolerated load must bring in exactly the two well-formed rows, "
        f"skipping the malformed one; got {loaded!r}")


# The node type is DERIVED from DescribeOrderableClusterOptions rather than pinned, because
# orderable node types differ by region and over time (dc2.large is not orderable in us-west-2).

_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded",
             "TooManyRequestsException", "SlowDown")
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
# Cheapest first; whatever this region actually offers for a single node wins.
_SINGLE_NODE_PREFERENCE = ("ra3.large", "rg.large", "ra3.xlplus")
MASTER_USERNAME = "adminuser"
MASTER_PASSWORD = "TestPassw0rd123"  # noqa: S105 - throwaway cluster deleted in teardown
DB_NAME = "devdb"
# A single-node ra3.large reaches `available` in ~105 s and a first statement lands in ~4 s; the
# deadlines are generous headroom, and a target that never converges FAILS instead of hanging.
_CLUSTER_DEADLINE_S = 1200
_STATEMENT_DEADLINE_S = 420

# Marks a failure where the control plane accepted a statement the engine never ran, so it is
# graded as a fidelity failure rather than an environment error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying ONLY on API throttling: a rate limit is infrastructure noise, never a
    behavioral observation."""
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
