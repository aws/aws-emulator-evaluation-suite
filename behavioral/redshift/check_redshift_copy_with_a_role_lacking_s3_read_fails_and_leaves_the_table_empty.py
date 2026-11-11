"""redshift-copy-with-a-role-lacking-s3-read-fails-and-leaves-the-table-empty."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redshift-copy-with-a-role-lacking-s3-read-fails-and-leaves-the-table-empty"
GROUP = 'sql-rejection'
SERVICES = ['redshift']


# ===== helpers =====

_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)

# Marks "the control plane accepted the SQL but the engine never did the work" as a data-plane
# failure rather than an environment error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit, not a behavioral observation)."""
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
# A single-node dc2.large typically reaches `available` in ~60-90 s; the deadline is headroom.
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
    """A role Redshift can assume, with one inline policy."""
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


_TABLE = "sim2real_behav_copy_denied"
_ROWS = [(i, f"row-{i:02d}") for i in range(1, 11)]


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A COPY whose IAM_ROLE cannot read the source fails with S3's refusal naming that assumed role
    and loads zero rows; the identical COPY naming the permitted attached role loads all ten."""
    # Reference: https://docs.aws.amazon.com/redshift/latest/dg/copy-parameters-authorization.html
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    scenario = "rs-copydeny"
    bucket = ctx.unique_name("sim2real-behav-rs-copydeny-")
    # Registered BEFORE the create it undoes, so a failure between the two cannot leak.
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    _create_bucket(s3, ctx.region, bucket, scenario)

    key = "sim2real-behav/rows.csv"
    body = "\n".join(f"{i},{v}" for i, v in _ROWS) + "\n"
    _retrying(lambda: s3.put_object(Bucket=bucket, Key=key, Body=body.encode(),
                                    Tagging="sim2real=" + scenario))

    permitted_name = ctx.unique_name("sim2real-behav-rs-copydeny-ok-role-")
    ctx.on_cleanup(lambda: _delete_role(iam, permitted_name))
    permitted_arn = _create_role(iam, permitted_name, {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"],
             "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
             "Resource": f"arn:aws:s3:::{bucket}"},
        ],
    }, scenario)

    # The one broken thing: an identically-trusted, identically-attached role whose policy grants
    # nothing on THIS bucket. It is not policy-less -- a role with no permissions at all could fail
    # for a different reason -- it simply cannot read this prefix.
    denied_name = ctx.unique_name("sim2real-behav-rs-copydeny-no-role-")
    ctx.on_cleanup(lambda: _delete_role(iam, denied_name))
    denied_arn = _create_role(iam, denied_name, {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"],
             "Resource": "arn:aws:s3:::sim2real-behav-no-such-bucket-for-copydeny/*"},
        ],
    }, scenario)

    cluster_id = ctx.unique_name("sim2real-behav-rs-copydeny-")
    # A provisioned Redshift cluster is the single most expensive leak in this service, so this is
    # registered before the identifier is used anywhere.
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    _create_cluster(rs, cluster_id, IamRoles=[permitted_arn, denied_arn],
                    Tags=[{"Key": "sim2real", "Value": scenario}])
    _wait_for_cluster_available(rs, cluster_id)

    attached = sorted(r["IamRoleArn"] for r in _retrying(
        lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))["Clusters"][0]["IamRoles"])
    assert attached == sorted([permitted_arn, denied_arn]), (
        f"BOTH roles must be attached, so the only difference between the two legs is the ARN the "
        f"statement names; got {attached!r}"
    )

    _run_sql(rsd, cluster_id, f"CREATE TABLE {_TABLE} (id INT, v VARCHAR(32))")
    ctx.on_cleanup(lambda: _describe_sql(rsd, cluster_id, f"DROP TABLE IF EXISTS {_TABLE}",
                                         timeout_s=120))

    def _copy(role_arn):
        return (f"COPY {_TABLE} (id, v) FROM 's3://{bucket}/{key}' "
                f"IAM_ROLE '{role_arn}' CSV")

    denied = _describe_sql(rsd, cluster_id, _copy(denied_arn))
    assert denied["Status"] == "FAILED", (
        f"a COPY under a role that cannot read the prefix must FAIL, got {denied['Status']!r} "
        f"error={denied.get('Error')!r}"
    )
    error = denied.get("Error") or ""
    assert "S3ServiceException" in error, (
        f"the failure must be S3's, raised inside the cluster's own request, got {error!r}"
    )
    # The refusal is the IAM not-authorized wording, not "Access Denied", and names the assumed role
    # and the refused action. ListBucket fails first because COPY resolves the prefix before reading.
    # The role name proves the cluster assumed the role the STATEMENT named.
    assert f"assumed-role/{denied_name}/RedshiftIamRoleSession" in error, (
        f"the cluster must have assumed the role the COPY statement named, so the refusal must "
        f"name {denied_name!r}; got {error!r}"
    )
    assert "is not authorized to perform: s3:ListBucket" in error, (
        f"the refusal must name the S3 action the assumed role was denied, got {error!r}"
    )
    assert f'resource: "arn:aws:s3:::{bucket}"' in error, (
        f"the refusal must name the source bucket the role could not read, got {error!r}"
    )
    assert permitted_name not in error, (
        f"the failure must be attributed to the denied role alone; the permitted role "
        f"{permitted_name!r} appears in {error!r}"
    )

    # Effect absent.
    after_denied = _select(rsd, cluster_id, f"SELECT count(*) FROM {_TABLE}")
    assert after_denied == [[{"longValue": 0}]], (
        f"a denied COPY must ingest nothing, but the table holds {after_denied!r} rows"
    )

    # POSITIVE CONTROL: identical statement, same cluster, same object, permitted ARN.
    control = _describe_sql(rsd, cluster_id, _copy(permitted_arn))
    assert control["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: the identical COPY under the permitted role must FINISH, got "
        f"{control['Status']!r} error={control.get('Error')!r}"
    )
    loaded = _select(rsd, cluster_id, f"SELECT id, v FROM {_TABLE} ORDER BY id")
    assert [(_cell(r, 0), _cell(r, 1)) for r in loaded] == _ROWS, (
        f"the permitted role must load every row of the object, got {loaded!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
