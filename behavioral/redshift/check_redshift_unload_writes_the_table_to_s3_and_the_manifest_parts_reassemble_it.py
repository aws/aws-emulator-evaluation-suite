"""redshift-unload-writes-the-table-to-s3-and-the-manifest-parts-reassemble-it."""

from __future__ import annotations

import json
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redshift-unload-writes-the-table-to-s3-and-the-manifest-parts-reassemble-it"
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

# Marks a data-plane failure, so "the control plane accepted the UNLOAD and the engine wrote
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
# Teardown has 1800 s in all: the DROP teardown before it takes up to 120 s and the role and bucket
# deletes after it need a margin, so the cluster delete and its wait for ClusterNotFound take what
# is left.
_DELETE_CLUSTER_DEADLINE_S = 1500
_CLUSTER_DEADLINE_S = 900
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
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


def _list_keys(s3, bucket, prefix):
    """Every key under *prefix*, fully paginated — an UNLOAD names its parts itself, so the
    listing must enumerate rather than guess."""
    keys = set()
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.update(o["Key"] for o in page.get("Contents", []))
    return keys


def _delete_bucket(s3, name):
    """Fully paginated empty-then-delete. An UNLOAD leaves objects with SERVER-chosen names, so
    the teardown must enumerate the bucket rather than guess the keys."""
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


_TABLE = "sim2real_behav_unload"
_ROWS = [(i, f"row-{i:02d}") for i in range(1, 51)]
_PREFIX = "sim2real-behav/out/"


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UNLOAD writes a known 50-row table to S3; every manifest part exists with its stated
    content_length, and the parts reassembled are exactly the rows the table holds."""
    # Reference: https://docs.aws.amazon.com/redshift/latest/dg/r_UNLOAD.html
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    scenario = "rs-unload"
    bucket = ctx.unique_name("sim2real-behav-rs-unload-")
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    _create_bucket(s3, ctx.region, bucket, scenario)

    role_name = ctx.unique_name("sim2real-behav-rs-unload-role-")
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    role_arn = _create_role(iam, role_name, {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
             "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
             "Resource": f"arn:aws:s3:::{bucket}"},
        ],
    }, scenario)

    cluster_id = ctx.unique_name("sim2real-behav-rs-unload-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    _create_cluster(rs, cluster_id, IamRoles=[role_arn],
                    Tags=[{"Key": "sim2real", "Value": scenario}])
    _wait_for_cluster_available(rs, cluster_id)

    _run_sql(rsd, cluster_id, f"CREATE TABLE {_TABLE} (id INT, v VARCHAR(32))")
    ctx.on_cleanup(lambda: _describe_sql(rsd, cluster_id, f"DROP TABLE IF EXISTS {_TABLE}",
                                         timeout_s=120))
    _run_sql(rsd, cluster_id, f"INSERT INTO {_TABLE} VALUES " + ", ".join(
        f"({i}, '{v}')" for i, v in _ROWS))

    # In-cluster truth first: the comparison is table-vs-S3, not literal-vs-S3, so a table that
    # did not hold what was inserted cannot be mistaken for a faithful UNLOAD.
    in_cluster = _select(rsd, cluster_id, f"SELECT id, v FROM {_TABLE} ORDER BY id")
    assert [(_cell(r, 0), _cell(r, 1)) for r in in_cluster] == _ROWS, (
        f"setup did not leave the 50 known rows in the table: {in_cluster!r}"
    )

    unload_sql = (
        f"UNLOAD ('SELECT id, v FROM {_TABLE}') TO 's3://{bucket}/{_PREFIX}' "
        f"IAM_ROLE '{role_arn}' MANIFEST DELIMITER '|' ALLOWOVERWRITE"
    )
    unload_status = _describe_sql(rsd, cluster_id, unload_sql)
    assert unload_status["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: UNLOAD must FINISH, got {unload_status['Status']!r} "
        f"error={unload_status.get('Error')!r}"
    )

    listed = _list_keys(s3, bucket, _PREFIX)
    manifest_key = f"{_PREFIX}manifest"
    assert manifest_key in listed, (
        f"MANIFEST must write {manifest_key!r}; the prefix holds {sorted(listed)!r}"
    )
    manifest = json.loads(
        _retrying(lambda: s3.get_object(Bucket=bucket, Key=manifest_key))["Body"].read())
    entries = manifest["entries"]
    assert len(entries) >= 1, f"the manifest must name at least one part: {manifest!r}"

    # Parsed structurally: an s3:// URL is not a string to split on '/', and a part key contains
    # the delimiter.
    part_keys = []
    for entry in entries:
        parsed = urllib.parse.urlparse(entry["url"])
        assert parsed.scheme == "s3" and parsed.netloc == bucket, (
            f"a manifest entry must name an s3 URL in {bucket!r}, got {entry['url']!r}"
        )
        part_keys.append(parsed.path.lstrip("/"))
    assert set(part_keys) <= listed, (
        f"the manifest names a key that is not in S3: {sorted(set(part_keys) - listed)!r}; the "
        f"prefix holds {sorted(listed)!r}"
    )

    unloaded_lines, part_sizes = [], []
    for key in part_keys:
        body = _retrying(lambda k=key: s3.get_object(Bucket=bucket, Key=k))["Body"].read()
        part_sizes.append(len(body))
        unloaded_lines.extend(
            line for line in body.decode().split("\n") if line)

    expected_lines = [f"{i}|{v}" for i, v in _ROWS]
    assert sorted(unloaded_lines) == sorted(expected_lines), (
        f"{DATAPLANE_MARKER}: the unloaded parts must reassemble into the table's rows; got "
        f"{len(unloaded_lines)} unloaded lines vs {len(expected_lines)} table rows; first "
        f"difference {next(iter(set(unloaded_lines) ^ set(expected_lines)), None)!r}"
    )
    assert [e["meta"]["content_length"] for e in entries] == part_sizes, (
        f"each manifest entry's content_length must equal the object it names; manifest says "
        f"{[e['meta']['content_length'] for e in entries]!r}, S3 holds {part_sizes!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
