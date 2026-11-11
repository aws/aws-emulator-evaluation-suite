"""redshift-wlm-queue-assignment-is-observable-in-the-cluster-system-tables."""

from __future__ import annotations

import json
import time


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redshift-wlm-queue-assignment-is-observable-in-the-cluster-system-tables"
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
# Teardown has 1800 s in all and this runs first; the parameter group delete after it takes up to
# 120 s, so the cluster delete and its wait for ClusterNotFound take what is left.
_DELETE_CLUSTER_DEADLINE_S = 1560
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


def _run_batch(rsd, cluster_id, sqls, timeout_s=_STATEMENT_DEADLINE_S):
    """BatchExecuteStatement runs the array serially in ONE transaction — the only Data API path
    that gives a check a multi-statement transaction, which is what makes a session-scoped `SET`
    and a contended `UPDATE`/`COMMIT` expressible at all."""
    batch_id = _retrying(lambda: rsd.batch_execute_statement(
        ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=ADMIN_USERNAME, Sqls=sqls))["Id"]
    return _wait_statement(rsd, batch_id, timeout_s=timeout_s)


def _delete_parameter_group(rs, name):
    """A parameter group cannot be deleted while ANY cluster still references it; the cluster
    teardown waits for ClusterNotFound first, so this retries InvalidClusterParameterGroupState
    only briefly and raises anything else."""
    deadline = time.monotonic() + 120
    while True:
        try:
            rs.delete_cluster_parameter_group(ParameterGroupName=name)
            return
        except ClientError as exc:
            if _code_of(exc) in ("ClusterParameterGroupNotFound",
                                 "ClusterParameterGroupNotFoundFault"):
                return
            if _code_of(exc) != "InvalidClusterParameterGroupState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)

# Two manual WLM queues: one matched by the query_group label, then the default queue. Manual WLM
# (rather than auto) is what makes the routing decision deterministic and therefore assertable.
_WLM = [
    {"query_group": ["sim2real"], "query_group_wild_card": 0, "query_concurrency": 2},
    {"query_concurrency": 3},
]
_PARAM_FAMILY = "redshift-1.0"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A statement run after `SET query_group` is recorded in stl_wlm_query under the matching WLM
    queue's service class, while the same statement without the label lands in a different one."""
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    scenario = "rs-wlm"
    group_name = ctx.unique_name("sim2real-behav-rs-wlm-pg-")
    # A parameter group cannot be deleted while a cluster references it, and the cluster teardown
    # registered next only STARTS an async delete -- so _delete_parameter_group waits it out.
    ctx.on_cleanup(lambda: _delete_parameter_group(rs, group_name))
    _retrying(lambda: rs.create_cluster_parameter_group(
        ParameterGroupName=group_name, ParameterGroupFamily=_PARAM_FAMILY,
        Description="sim2real-behav redshift " + scenario,
        Tags=[{"Key": "sim2real", "Value": scenario}]))
    _retrying(lambda: rs.modify_cluster_parameter_group(
        ParameterGroupName=group_name,
        Parameters=[{"ParameterName": "wlm_json_configuration",
                     "ParameterValue": json.dumps(_WLM)}]))

    stored = {p["ParameterName"]: p["ParameterValue"] for p in _retrying(
        lambda: rs.describe_cluster_parameters(ParameterGroupName=group_name))["Parameters"]}
    assert json.loads(stored["wlm_json_configuration"]) == _WLM, (
        f"the parameter group must hold the WLM configuration as given, got "
        f"{stored.get('wlm_json_configuration')!r}"
    )

    cluster_id = ctx.unique_name("sim2real-behav-rs-wlm-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    # Applied AT CREATE rather than through ModifyCluster: wlm_json_configuration is a static
    # parameter that otherwise needs a reboot, and a cluster booted with the group already
    # attached reaches `in-sync` without one.
    _create_cluster(rs, cluster_id, ClusterParameterGroupName=group_name,
                    Tags=[{"Key": "sim2real", "Value": scenario}])
    _wait_for_cluster_available(rs, cluster_id)

    def _apply_status():
        cluster = _retrying(
            lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))["Clusters"][0]
        matching = [g for g in cluster["ClusterParameterGroups"]
                    if g["ParameterGroupName"] == group_name]
        return matching[0]["ParameterApplyStatus"] if matching else None

    apply_status = _wait_until(_apply_status, lambda s: s == "in-sync", timeout_s=600,
                               interval_s=15,
                               what=f"parameter group {group_name} to report in-sync")
    assert apply_status == "in-sync", (
        f"the cluster must report the WLM parameter group as applied, got {apply_status!r}"
    )

    # One batch is one session, so the SET and the query it labels are the same session -- which
    # is the only way a session-scoped query_group is expressible through the Data API.
    tagged = _run_batch(rsd, cluster_id, [
        "SET query_group TO 'sim2real'",
        "SELECT count(*) FROM stv_recents",
    ])
    assert tagged["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: the labelled batch must FINISH, got {tagged['Status']!r} "
        f"error={tagged.get('Error')!r}"
    )
    tagged_qid = tagged["SubStatements"][-1]["RedshiftQueryId"]

    untagged_id = _submit(rsd, cluster_id, "SELECT count(*) FROM stv_recents")
    untagged = _wait_statement(rsd, untagged_id)
    assert untagged["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: the unlabelled statement must FINISH, got "
        f"{untagged['Status']!r} error={untagged.get('Error')!r}"
    )
    untagged_qid = untagged["RedshiftQueryId"]
    assert tagged_qid and untagged_qid and tagged_qid != untagged_qid, (
        f"the two statements must be two distinct cluster queries, got {tagged_qid!r} and "
        f"{untagged_qid!r}"
    )

    def _wlm_rows():
        return _select(rsd, cluster_id,
                       "SELECT query, service_class, "
                       "CASE WHEN queue_start_time IS NULL THEN 0 ELSE 1 END "
                       f"FROM stl_wlm_query WHERE query IN ({tagged_qid}, {untagged_qid}) "
                       "ORDER BY query")
    rows = _wait_until(_wlm_rows, lambda r: len(r) >= 2, timeout_s=180, interval_s=10,
                       what="stl_wlm_query to account for both queries")
    by_query = {_cell(r, 0): (_cell(r, 1), _cell(r, 2)) for r in rows}
    assert sorted(by_query) == sorted([tagged_qid, untagged_qid]), (
        f"stl_wlm_query must hold exactly the two queries run here, got {by_query!r} for "
        f"{tagged_qid!r} and {untagged_qid!r}"
    )
    tagged_class, tagged_queued = by_query[tagged_qid]
    untagged_class, untagged_queued = by_query[untagged_qid]

    assert tagged_class != untagged_class, (
        f"the labelled and unlabelled statements must land in DIFFERENT WLM service classes; "
        f"both landed in {tagged_class!r}, so query_group routing did nothing"
    )
    assert tagged_class >= 6, (
        f"a query_group-matched queue is a user-defined service class (6 and up), got "
        f"{tagged_class!r}"
    )
    assert untagged_class >= 6, (
        f"the unlabelled statement must land in the configured DEFAULT user queue, not a system "
        f"service class; got {untagged_class!r}"
    )
    assert (tagged_queued, untagged_queued) == (1, 1), (
        f"every WLM-managed query is queued before it runs, so both rows must carry a "
        f"queue_start_time; got tagged={tagged_queued!r} untagged={untagged_queued!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
