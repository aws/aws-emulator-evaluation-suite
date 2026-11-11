"""get-cluster-credentials-autocreate-creates-db-user."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-cluster-credentials-autocreate-creates-db-user"
GROUP = 'data-plane'
SERVICES = ['redshift']

# The identity GetClusterCredentials returns is the requested
# DbUser under one of two prefixes, and the prefix is the ONLY observable difference AutoCreate
# makes. "IAMA" = IAM, Auto-create; "IAM" = IAM, must already exist.
_AUTOCREATE_PREFIX = "IAMA:"
_PLAIN_PREFIX = "IAM:"


# ===== helpers =====

_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
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


def _err(fn):
    """Call *fn*; return the (code, message) of the AWS error it raises, or ("OK", None)."""
    try:
        _retrying(fn)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    return "OK", None


def _wait_until(probe, done, timeout_s, interval_s, what="condition"):
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


NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")
ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"
DB_NAME = "devdb"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_CLUSTER_DEADLINE_S = 1200
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
_STATEMENT_DEADLINE_S = 420


def _node_type(rs, cluster_type="single-node"):
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
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    params.update(overrides)
    return params


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


# The ClusterDeleted waiter allows 1800 s, the redshift teardown budget; keep a 60 s margin.
_TEARDOWN_S = 1740.0


def _wait_for_cluster_gone(rs, cluster_id, deadline):
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
            raise TimeoutError(f"cluster {cluster_id} still listed ({status!r}) at the teardown deadline")
        time.sleep(2)


def _delete_cluster(rs, cluster_id):
    """Teardown: DeleteCluster without a final snapshot (the auto-created database user goes with the
    cluster), retrying InvalidClusterState every 2 s, then wait for ClusterNotFound; one deadline."""
    deadline = time.monotonic() + _TEARDOWN_S
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
    _wait_for_cluster_gone(rs, cluster_id, deadline)


def _wait_statement(rsd, statement_id, timeout_s=_STATEMENT_DEADLINE_S):
    return _wait_until(
        lambda: _retrying(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s,
        interval_s=5,
        what=f"statement {statement_id} to reach a terminal status",
    )


def _select(rsd, cluster_id, sql):
    """Run a SELECT through the Data API and return its Records."""
    statement_id = _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=ADMIN_USERNAME, Sql=sql
        )
    )["Id"]
    described = _wait_statement(rsd, statement_id)
    assert described["Status"] == "FINISHED", (
        f"SQL {sql!r} did not FINISH: status={described['Status']!r} error={described.get('Error')!r}"
    )
    return _retrying(lambda: rsd.get_statement_result(Id=statement_id))["Records"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetClusterCredentials with AutoCreate=True mints a fresh password whose Expiration honours
    DurationSeconds and returns the `IAMA:<name>` identity (`IAM:<name>` without it), yet creates no
    database user: a Data API statement as that DbUser still fails with "does not exist"."""
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    cluster_id = ctx.unique_name("sim2real-behav-rs-creds-")
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    rs.create_cluster(**_cluster_params(rs, cluster_id))
    _wait_for_cluster_available(rs, cluster_id)

    db_user = "sim2real_behav_tempuser"
    before = _select(
        rsd, cluster_id, f"SELECT usename FROM pg_user WHERE usename LIKE '%{db_user}'"
    )
    assert before == [], f"the auto-created user must not exist before the call, got {before!r}"

    minted = _retrying(
        lambda: rs.get_cluster_credentials(
            ClusterIdentifier=cluster_id,
            DbUser=db_user,
            DbName=DB_NAME,
            AutoCreate=True,
            DurationSeconds=900,
        )
    )
    returned_user = minted["DbUser"]
    assert returned_user.endswith(db_user), (
        f"the minted DbUser must be derived from the requested name {db_user!r}, got {returned_user!r}"
    )
    assert minted["DbPassword"], "GetClusterCredentials must return a DbPassword"
    assert minted["DbPassword"] != ADMIN_PASSWORD, (
        "the minted temporary password must not be the cluster's admin password"
    )
    expiration_900 = minted["Expiration"]
    assert expiration_900 is not None, "GetClusterCredentials must return an Expiration"

    # AutoCreate=True is recorded in the identity itself: the "IAMA:" prefix is the auto-create
    # marker (see _AUTOCREATE_PREFIX), and it is exactly one prefix away from what
    # the same request WITHOUT AutoCreate returns.
    assert returned_user == f"{_AUTOCREATE_PREFIX}{db_user}", (
        f"AutoCreate=True must mint the auto-create identity {_AUTOCREATE_PREFIX}{db_user!r}, got "
        f"{returned_user!r}"
    )
    plain = _retrying(
        lambda: rs.get_cluster_credentials(
            ClusterIdentifier=cluster_id, DbUser=db_user, DbName=DB_NAME, DurationSeconds=900
        )
    )
    assert plain["DbUser"] == f"{_PLAIN_PREFIX}{db_user}", (
        f"omitting AutoCreate must mint the plain identity {_PLAIN_PREFIX}{db_user!r}, got "
        f"{plain['DbUser']!r}"
    )
    assert plain["DbUser"] != returned_user, (
        "AutoCreate must change the minted identity; an emulator that ignores the flag returns "
        f"{plain['DbUser']!r} for both"
    )

    # Cross-plane, positively asserted: the mint did NOT create a database user. The Data API
    # authenticates a DbUser as the plain "IAM:" identity, so running anything as the requested user
    # fails asynchronously with a FATAL naming that identity as nonexistent.
    as_user = _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=db_user, Sql="SELECT current_user"
        )
    )
    as_user_final = _wait_statement(rsd, as_user["Id"])
    assert as_user_final["Status"] == "FAILED", (
        "GetClusterCredentials(AutoCreate=True) does not create the database user, so a Data API "
        f"statement run as {db_user!r} must FAIL; got {as_user_final.get('Status')!r}"
    )
    assert f'user "{_PLAIN_PREFIX}{db_user}" does not exist' in (as_user_final.get("Error") or ""), (
        "the failure must name the plain IAM: identity as nonexistent -- that is what proves the "
        f"auto-create is deferred to a real connection; got {as_user_final.get('Error')!r}"
    )
    # ...and the minted user is in none of the three user catalogues, under either prefix.
    after = _select(
        rsd, cluster_id, f"SELECT usename FROM pg_user WHERE usename LIKE '%{db_user}'"
    )
    assert after == [], (
        f"no pg_user row may exist for {db_user!r} until the credentials are used to connect; got "
        f"{after!r}"
    )

    # A second mint for the same user: existing user, new secret, longer window.
    longer = _retrying(
        lambda: rs.get_cluster_credentials(
            ClusterIdentifier=cluster_id,
            DbUser=db_user,
            DbName=DB_NAME,
            AutoCreate=True,
            DurationSeconds=3600,
        )
    )
    assert longer["DbUser"] == returned_user, (
        f"re-minting must reuse the same user name, got {longer['DbUser']!r} vs {returned_user!r}"
    )
    assert longer["DbPassword"] != minted["DbPassword"], (
        "each GetClusterCredentials call must mint a FRESH password — an emulator returning a "
        "constant secret is a fidelity gap"
    )
    window = (longer["Expiration"] - expiration_900).total_seconds()
    assert window > 2000, (
        "Expiration must honour DurationSeconds (3600s vs 900s is a ~2700s difference); the two "
        f"expirations differ by only {window}s, so DurationSeconds is being ignored"
    )

    # Break exactly one thing: DurationSeconds below the documented 900s minimum.
    too_short, too_short_message = _err(
        lambda: rs.get_cluster_credentials(
            ClusterIdentifier=cluster_id,
            DbUser="sim2real_behav_shortuser",
            DbName=DB_NAME,
            AutoCreate=True,
            DurationSeconds=60,
        )
    )
    assert too_short == "InvalidParameterValue", (
        f"DurationSeconds=60 is below the 900s minimum and must be rejected, got {too_short}"
    )
    assert too_short_message == "Token duration must be between 900 and 3600 seconds", too_short_message
    # Effect absent: the rejected call must not have auto-created its user. On real Redshift no
    # mint of any kind creates a pg_user row (see the docstring), so this specifically catches an
    # emulator that creates users EAGERLY on GetClusterCredentials -- and it must not do so even on
    # a call it rejected.
    leaked = _select(
        rsd, cluster_id, "SELECT usename FROM pg_user WHERE usename LIKE '%sim2real_behav_shortuser'"
    )
    assert leaked == [], (
        f"a rejected GetClusterCredentials must not create the database user, got {leaked!r}"
    )

    # Control: a valid duration for that same new user still mints a usable credential.
    control = _retrying(
        lambda: rs.get_cluster_credentials(
            ClusterIdentifier=cluster_id,
            DbUser="sim2real_behav_shortuser",
            DbName=DB_NAME,
            AutoCreate=True,
            DurationSeconds=900,
        )
    )
    assert control["DbPassword"], control
    assert control["DbUser"] == f"{_AUTOCREATE_PREFIX}sim2real_behav_shortuser", (
        f"the control mint must return the auto-create identity, got {control['DbUser']!r}"
    )
    assert control["DbPassword"] != minted["DbPassword"], (
        "the control mint must still be a fresh secret, not a replay of the first user's password"
    )
    assert control["Expiration"] > expiration_900, (
        f"the control mint must expire after the first one, got {control['Expiration']} <= "
        f"{expiration_900}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
