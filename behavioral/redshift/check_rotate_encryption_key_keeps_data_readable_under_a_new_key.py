"""rotate-encryption-key-keeps-data-readable-under-a-new-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rotate-encryption-key-keeps-data-readable-under-a-new-key"
GROUP = "cluster-lifecycle"
SERVICES = ["redshift"]

_ADMIN_USER = "sim2realadmin"
_DB_NAME = "sim2realdb"
_TABLE = "sim2real_rotate_probe"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
_THROTTLE_CODES = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException")


def _api_code(exc) -> str:
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _call_with_retry(fn, *, attempts: int = 6, backoff_s: float = 5.0):
    """Retries only a request-rate throttle; any other outcome propagates on the first try."""
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _api_code(exc) not in _THROTTLE_CODES:
                raise
            last_exc = exc
            time.sleep(backoff_s * (attempt + 1))
    raise last_exc


def _poll_until(probe, is_done, *, timeout_s: float, interval_s: float, what: str):
    """Polls probe() until is_done(value) is true; raises on timeout, never returns a stale value."""
    deadline = time.monotonic() + timeout_s
    while True:
        observed = probe()
        if is_done(observed):
            return observed
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last={observed!r}")
        time.sleep(interval_s)


def _cheapest_single_node_type(rs) -> str:
    seen = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        page = _call_with_retry(lambda: rs.describe_orderable_cluster_options(**kwargs))
        for option in page.get("OrderableClusterOptions", []):
            if option.get("ClusterType") == "single-node":
                node_type = option.get("NodeType")
                if node_type and node_type not in seen:
                    seen.append(node_type)
        marker = page.get("Marker")
        if not marker:
            break
    for preferred in _NODE_TYPE_PREFERENCE:
        if preferred in seen:
            return preferred
    assert seen, "no single-node orderable cluster options in this region"
    return sorted(seen)[0]


def _describe_cluster(rs, cluster_id):
    try:
        clusters = _call_with_retry(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))["Clusters"]
    except ClientError as exc:
        if _api_code(exc) in _NOT_FOUND_CLUSTER:
            return None
        raise
    return clusters[0] if clusters else None


def _wait_cluster_status(rs, cluster_id, *, want: set[str], timeout_s: float, interval_s: float = 15.0):
    def probe():
        cluster = _describe_cluster(rs, cluster_id)
        return cluster["ClusterStatus"] if cluster else None

    return _poll_until(probe, lambda status: status in want, timeout_s=timeout_s, interval_s=interval_s,
                        what=f"cluster status in {sorted(want)}")


def _delete_cluster_until_gone(rs, cluster_id, *, timeout_s: float = 600.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as exc:
            code = _api_code(exc)
            if code in _NOT_FOUND_CLUSTER:
                return
            if code != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    _poll_until(lambda: _describe_cluster(rs, cluster_id), lambda c: c is None,
                timeout_s=timeout_s, interval_s=10.0, what=f"cluster {cluster_id} to disappear")


def _run_sql(rsd, cluster_id, sql, *, timeout_s: float):
    """ExecuteStatement, polled to a terminal status; raises unless it FINISHED."""
    statement_id = _call_with_retry(lambda: rsd.execute_statement(
        ClusterIdentifier=cluster_id, Database=_DB_NAME, DbUser=_ADMIN_USER, Sql=sql,
    ))["Id"]
    described = _poll_until(
        lambda: _call_with_retry(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s, interval_s=3.0, what=f"statement {statement_id} to reach a terminal status",
    )
    assert described["Status"] == "FINISHED", (
        f"SQL {sql!r} did not FINISH: status={described['Status']!r} error={described.get('Error')!r}"
    )
    return statement_id


def _first_cell(rsd, statement_id):
    """The first row's first column of a statement's result, or None if there is no row."""
    page = _call_with_retry(lambda: rsd.get_statement_result(Id=statement_id))
    records = page.get("Records", [])
    if not records:
        return None
    field = records[0][0]
    if field.get("isNull"):
        return None
    return next(iter(field.values()))


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data",
)
def run(ctx) -> None:
    """A row written through the Data API before RotateEncryptionKey reads back unchanged, through
    a fresh statement, once the cluster settles under its new KMS key.

    Reference: https://docs.aws.amazon.com/redshift/latest/APIReference/API_RotateEncryptionKey.html
    """
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    cluster_id = ctx.unique_name("sim2real-rs-rotate-")
    password = "Sim2realRotate9!" + cluster_id[-6:]
    node_type = _cheapest_single_node_type(rs)
    _call_with_retry(lambda: rs.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=node_type,
        ClusterType="single-node",
        MasterUsername=_ADMIN_USER,
        MasterUserPassword=password,
        DBName=_DB_NAME,
        PubliclyAccessible=False,
        Encrypted=True,
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    ))
    ctx.on_cleanup(lambda: _delete_cluster_until_gone(rs, cluster_id))

    _wait_cluster_status(rs, cluster_id, want={"available"}, timeout_s=900.0)
    before = _describe_cluster(rs, cluster_id)
    assert before["Encrypted"] is True, f"expected the new cluster encrypted, got Encrypted={before['Encrypted']!r}"
    key_before = before["KmsKeyId"]

    _run_sql(rsd, cluster_id, f"CREATE TABLE {_TABLE} (id INT NOT NULL, note VARCHAR(64) NOT NULL)", timeout_s=120.0)
    _run_sql(rsd, cluster_id, f"INSERT INTO {_TABLE} (id, note) VALUES (1, 'before-rotation')", timeout_s=60.0)
    read_before_id = _run_sql(rsd, cluster_id, f"SELECT note FROM {_TABLE} WHERE id = 1", timeout_s=60.0)
    seen_before = _first_cell(rsd, read_before_id)
    assert seen_before == "before-rotation", f"row did not read back before rotation, got {seen_before!r}"

    started = _call_with_retry(lambda: rs.rotate_encryption_key(ClusterIdentifier=cluster_id))["Cluster"]
    assert started["ClusterStatus"] == "rotating-keys", (
        f"RotateEncryptionKey's own response reported ClusterStatus={started['ClusterStatus']!r}, "
        "expected the transition to start as 'rotating-keys'"
    )

    settled_status = _wait_cluster_status(rs, cluster_id, want={"available"}, timeout_s=600.0)
    assert settled_status == "available", f"cluster settled in {settled_status!r} after rotation, expected 'available'"

    settled = _describe_cluster(rs, cluster_id)
    assert settled["Encrypted"] is True, f"cluster lost Encrypted after rotation: {settled['Encrypted']!r}"
    key_after = settled["KmsKeyId"]
    assert key_after == key_before, (
        f"KmsKeyId reported after the rotation ({key_after!r}) no longer matches the cluster's "
        f"KMS key ({key_before!r}); RotateEncryptionKey rotates the data and cluster encryption "
        "keys underneath it, not which KMS key protects them"
    )

    read_after_id = _run_sql(rsd, cluster_id, f"SELECT note FROM {_TABLE} WHERE id = 1", timeout_s=180.0)
    seen_after = _first_cell(rsd, read_after_id)
    assert seen_after == "before-rotation", (
        f"row written before the key rotation read back as {seen_after!r} afterward"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
