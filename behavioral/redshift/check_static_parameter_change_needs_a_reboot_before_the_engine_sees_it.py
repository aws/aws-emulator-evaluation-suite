"""static-parameter-change-needs-a-reboot-before-the-engine-sees-it."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "static-parameter-change-needs-a-reboot-before-the-engine-sees-it"
GROUP = "parameter-group"
SERVICES = ["redshift"]


# ===== helpers (self-contained) =====

_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)

# Failure prefix: the control plane accepted the change but the engine never ran anything.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")
ADMIN_USERNAME = "adminuser"
ADMIN_PASSWORD = "TestPassw0rd123"
DB_NAME = "devdb"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_INVALID_STATE = ("InvalidClusterState", "InvalidClusterStateFault")
_NOT_FOUND_PARAM_GROUP = ("ClusterParameterGroupNotFound", "ClusterParameterGroupNotFoundFault")
# A single-node dc2.large typically reaches `available` in ~60-90 s; the deadline is headroom.
_CLUSTER_DEADLINE_S = 900
_DELETE_CLUSTER_DEADLINE_S = 300
_DELETE_PARAM_GROUP_DEADLINE_S = 900
_TERMINAL_STATEMENT = ("FINISHED", "FAILED", "ABORTED")
# The first Data API statement against a freshly-available cluster includes connection
# establishment, so the first statement deadline is deliberately larger than a warm query's.
_STATEMENT_DEADLINE_S = 420
_WARM_STATEMENT_DEADLINE_S = 120
# A static parameter change is reported against the cluster asynchronously.
_PARAM_STATUS_DEADLINE_S = 300
# RebootCluster: the cluster leaves `available`, reboots, and returns.
_REBOOT_DEADLINE_S = 900

_PARAMETER = "enable_case_sensitive_identifier"
# Two of AWS's seven documented ParameterApplyStatus values describe a static change awaiting a
# reboot; the rest (in-sync, applying, invalid-parameter, apply-error, unknown-error) must NOT
# appear here. See
# https://docs.aws.amazon.com/redshift/latest/APIReference/API_ClusterParameterStatus.html
_AWAITING_REBOOT = ("pending-reboot", "apply-deferred")
# Substrings of the duplicate-column failure Redshift reports when case sensitivity is OFF.
_DUPLICATE_HINTS = ("already exists", "duplicate", "specified more than once")


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling."""
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_until(probe, done, timeout_s, interval_s, what="condition", ctx=None):
    """Poll *probe* every *interval_s* until *done*; raise on timeout, which is bounded by
    *timeout_s* and the check's remaining budget."""
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"waiting for {what}: the run budget ended first; not graded")
            raise AssertionError(
                f"timed out after {timeout_s:.0f}s waiting for {what}; last observed={observed!r}"
            )
        time.sleep(interval_s)


def _node_type(rs, cluster_type="single-node"):
    """Cheapest orderable node type for *cluster_type* in this region, read off the account."""
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
            raise AssertionError(
                f"no orderable {cluster_type} options in {rs.meta.region_name}; "
                f"DescribeOrderableClusterOptions returned nothing usable"
            )
        chosen = sorted(available)[0]
    return chosen


def _default_parameter_group_family(rs):
    """The parameter-group family, read from DescribeClusterVersions rather than pinned.

    A fresh account can list zero parameter groups, not even `default.*`, before using Redshift.
    """
    marker = None
    families = []
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = _retrying(lambda: rs.describe_cluster_versions(**kwargs))
        for version in resp.get("ClusterVersions", []):
            family = version.get("ClusterParameterGroupFamily")
            if family:
                families.append(family)
        marker = resp.get("Marker")
        if not marker:
            break
    if not families:
        raise AssertionError(
            "DescribeClusterVersions reported no ClusterParameterGroupFamily, so the account's "
            "parameter-group family cannot be derived; every AWS account and region offers at "
            "least one Redshift engine version"
        )
    # Highest-sorting default family: 'redshift-2.0' wins over 'redshift-1.0' when both exist.
    return sorted(families)[-1]


def _cluster_params(rs, cluster_id, **overrides):
    """Cheapest shape that proves the invariant: one node, private (the Data API needs no VPC),
    1-day snapshot retention (RA3 refuses 0)."""
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
    """CreateCluster with a bounded retry: a just-created parameter group or IAM role is not
    always visible to Redshift yet, and it rejects the association outright."""
    deadline = time.monotonic() + 180
    while True:
        try:
            return _retrying(
                lambda: rs.create_cluster(**_cluster_params(rs, cluster_id, **overrides))
            )
        except ClientError as exc:
            if (
                _code_of(exc)
                not in _INVALID_STATE + _NOT_FOUND_PARAM_GROUP + ("InvalidIamRoleFault",)
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(2)


def _describe_cluster(rs, cluster_id):
    """The cluster record, or None if it does not resolve."""
    try:
        resp = _retrying(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_CLUSTER:
            return None
        raise
    clusters = resp.get("Clusters", [])
    return clusters[0] if clusters else None


def _cluster_status(rs, cluster_id):
    cluster = _describe_cluster(rs, cluster_id)
    return cluster["ClusterStatus"] if cluster else None


def _wait_for_cluster_available(rs, cluster_id, timeout_s=_CLUSTER_DEADLINE_S, ctx=None):
    """Poll to a terminal creation state (failures included), then assert it is `available`."""
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
        interval_s=2,
        what=f"cluster {cluster_id} to reach a terminal creation state",
        ctx=ctx,
    )
    assert status == "available", (
        f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'"
    )
    return status


def _delete_cluster(rs, cluster_id):
    """Delete with SkipFinalClusterSnapshot, retrying while the cluster's state refuses it."""
    deadline = time.monotonic() + _DELETE_CLUSTER_DEADLINE_S
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as exc:
            code = _code_of(exc)
            if code in _NOT_FOUND_CLUSTER:
                return
            if code not in _INVALID_STATE + _THROTTLE or time.monotonic() >= deadline:
                raise
        time.sleep(3)


def _delete_parameter_group(rs, name):
    """Delete a parameter group, waiting out any cluster that still references it."""
    deadline = time.monotonic() + _DELETE_PARAM_GROUP_DEADLINE_S
    while True:
        try:
            rs.delete_cluster_parameter_group(ParameterGroupName=name)
            return
        except ClientError as exc:
            code = _code_of(exc)
            if code in _NOT_FOUND_PARAM_GROUP:
                return
            if (
                code
                not in ("InvalidClusterParameterGroupState",
                        "InvalidClusterParameterGroupStateFault") + _THROTTLE
                or time.monotonic() >= deadline
            ):
                raise
        time.sleep(3)


def _wait_statement(rsd, statement_id, timeout_s=_STATEMENT_DEADLINE_S, ctx=None):
    """Poll DescribeStatement to a TERMINAL status (SUBMITTED/PICKED/STARTED are transient)."""
    return _wait_until(
        lambda: _retrying(lambda: rsd.describe_statement(Id=statement_id)),
        lambda d: d.get("Status") in _TERMINAL_STATEMENT,
        timeout_s=timeout_s,
        interval_s=1,
        what=f"statement {statement_id} to reach a terminal status",
        ctx=ctx,
    )


def _submit(rsd, cluster_id, sql, **kwargs):
    return _retrying(
        lambda: rsd.execute_statement(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=ADMIN_USERNAME, Sql=sql,
            **kwargs,
        )
    )["Id"]


def _describe_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S, ctx=None):
    """Submit *sql*, wait for terminal, return the DescribeStatement WITHOUT asserting on it."""
    return _wait_statement(rsd, _submit(rsd, cluster_id, sql), timeout_s=timeout_s, ctx=ctx)


def _run_sql(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S, ctx=None):
    """Submit *sql*, wait for terminal, assert it FINISHED. Returns the statement id."""
    statement_id = _submit(rsd, cluster_id, sql)
    described = _wait_statement(rsd, statement_id, timeout_s=timeout_s, ctx=ctx)
    assert described["Status"] == "FINISHED", (
        f"{DATAPLANE_MARKER}: SQL {sql!r} did not FINISH: status={described['Status']!r} "
        f"error={described.get('Error')!r}"
    )
    return statement_id


def _cell(record, i):
    """The single scalar out of a Data API Field union cell, whatever member it used."""
    field = record[i]
    if field.get("isNull"):
        return None
    return next(iter(field.values()))


def _select(rsd, cluster_id, sql, timeout_s=_STATEMENT_DEADLINE_S, ctx=None):
    """Every row of a SELECT's result, paginated (GetStatementResult is token-paged)."""
    statement_id = _run_sql(rsd, cluster_id, sql, timeout_s=timeout_s, ctx=ctx)
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


def _flip(value):
    """The opposite of whatever boolean spelling the target reported, so no value is pinned."""
    pairs = (("true", "false"), ("on", "off"), ("1", "0"), ("TRUE", "FALSE"), ("ON", "OFF"))
    for low, high in pairs:
        if value == low:
            return high
        if value == high:
            return low
    return value


# DescribeClusterParameters spells this boolean 'true'/'false' but SHOW spells it 'on'/'off'.
_TRUTHY_SPELLINGS = {"true", "on", "1"}
_FALSY_SPELLINGS = {"false", "off", "0"}


def _as_bool(value):
    """The MEANING of whatever boolean spelling *value* uses, so a control-plane value and the
    engine's own SHOW value can be compared for equivalence rather than bytes."""
    low = value.lower()
    if low in _TRUTHY_SPELLINGS:
        return True
    if low in _FALSY_SPELLINGS:
        return False
    raise AssertionError(
        f"{value!r} is not a recognised boolean spelling; expected one of "
        f"{sorted(_TRUTHY_SPELLINGS | _FALSY_SPELLINGS)!r}"
    )


def _show(rsd, cluster_id, ctx=None):
    """`SHOW <parameter>` through the Data API, lowercased: the engine's view of the setting."""
    rows = _select(
        rsd, cluster_id, f"SHOW {_PARAMETER}", timeout_s=_WARM_STATEMENT_DEADLINE_S, ctx=ctx
    )
    assert len(rows) == 1 and len(rows[0]) == 1, (
        f"SHOW {_PARAMETER} must return exactly one row of one column, got {rows!r}"
    )
    shown = _cell(rows[0], 0)
    assert isinstance(shown, str) and shown, (
        f"SHOW {_PARAMETER} must return a non-empty string value, got {shown!r}"
    )
    return shown.lower()


# Reference: https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-parameter-groups.html
@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A static parameter change is stored by the control plane but the engine keeps the old
    behaviour (case-differing columns refused) until RebootCluster, after which the identical
    DDL succeeds.
    """
    rs = ctx.client("redshift")
    rsd = ctx.client("redshift-data")

    # Nothing hardcodes the account or region; the region comes from ctx.
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"STS must report a numeric account id, got {account!r}"
    )
    scenario = "rs-static-param-reboot"
    tag_set = [{"Key": "sim2real", "Value": scenario}]

    family = _default_parameter_group_family(rs)
    group_name = ctx.unique_name("sim2real-behav-rs-reboot-pg-")
    # Registered before creation so the cluster teardown (registered next) runs first: the
    # group cannot be deleted while a cluster holds it.
    ctx.on_cleanup(lambda: _delete_parameter_group(rs, group_name))
    _retrying(
        lambda: rs.create_cluster_parameter_group(
            ParameterGroupName=group_name,
            ParameterGroupFamily=family,
            Description=f"sim2real-behav redshift {scenario}",
            Tags=tag_set,
        )
    )

    # The parameter's own ApplyType says whether it needs a reboot; if it ever becomes dynamic,
    # the assertion fails instead of the check silently proving nothing.
    def _stored():
        return {
            p["ParameterName"]: p
            for p in _retrying(
                lambda: rs.describe_cluster_parameters(ParameterGroupName=group_name)
            )["Parameters"]
        }

    stored = _stored()
    assert _PARAMETER in stored, (
        f"parameter-group family {family!r} must expose {_PARAMETER!r}; "
        f"DescribeClusterParameters returned {sorted(stored)!r}"
    )
    descriptor = stored[_PARAMETER]
    assert descriptor.get("ApplyType") == "static", (
        f"{_PARAMETER!r} must be reported STATIC by the target itself — that is what makes a "
        f"reboot the contract — got ApplyType={descriptor.get('ApplyType')!r}"
    )
    assert descriptor.get("IsModifiable") is True, (
        f"{_PARAMETER!r} must be modifiable for this check to mean anything, got "
        f"IsModifiable={descriptor.get('IsModifiable')!r}"
    )
    baseline_value = descriptor.get("ParameterValue")
    assert baseline_value is not None, (
        f"DescribeClusterParameters must report a value for {_PARAMETER!r} before it is changed, "
        f"got {descriptor!r}"
    )
    # The value written is DERIVED by flipping whatever the target reported, so no literal
    # 'false'/'true' spelling is pinned and a family that spells it 'off'/'on' still works.
    flipped = _flip(baseline_value)
    assert flipped != baseline_value, (
        f"the baseline value {baseline_value!r} of {_PARAMETER!r} must be a recognised boolean "
        f"spelling so the check can derive its opposite; got no flip"
    )

    cluster_id = ctx.unique_name("sim2real-behav-rs-reboot-")
    # A provisioned Redshift cluster is the single most expensive leak in this service, so this is
    # registered before the identifier is used anywhere.
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    _create_cluster(rs, cluster_id, ClusterParameterGroupName=group_name, Tags=tag_set)

    # ClusterAvailabilityStatus is a second axis over ClusterStatus, asserted as an allowed pair
    # so a missing or copied field fails instead of skipping the leg.
    mid_create = _describe_cluster(rs, cluster_id)
    assert mid_create is not None, (
        f"DescribeClusters must resolve {cluster_id!r} immediately after CreateCluster returned"
    )
    early_pair = (mid_create["ClusterStatus"], mid_create.get("ClusterAvailabilityStatus"))
    assert early_pair in (("creating", "Modifying"), ("available", "Available")), (
        f"ClusterStatus and ClusterAvailabilityStatus are independent axes with a fixed "
        f"correspondence: 'creating' pairs with 'Modifying' and 'available' with 'Available'. "
        f"DescribeClusters reported {early_pair!r} just after CreateCluster"
    )

    _wait_for_cluster_available(rs, cluster_id, ctx=ctx)
    settled = _describe_cluster(rs, cluster_id)
    assert settled["ClusterAvailabilityStatus"] == "Available", (
        f"an `available` cluster must report ClusterAvailabilityStatus 'Available', got "
        f"{settled.get('ClusterAvailabilityStatus')!r}"
    )

    def _apply_status():
        cluster = _describe_cluster(rs, cluster_id)
        if cluster is None:
            return None
        matching = [
            g for g in cluster.get("ClusterParameterGroups", [])
            if g.get("ParameterGroupName") == group_name
        ]
        return matching[0].get("ParameterApplyStatus") if matching else None

    # Booted with the group already attached, so it settles in-sync with no reboot.
    _wait_until(
        _apply_status,
        lambda s: s == "in-sync",
        timeout_s=_PARAM_STATUS_DEADLINE_S,
        interval_s=2,
        what=f"parameter group {group_name} to report in-sync on a freshly booted cluster",
        ctx=ctx,
    )

    mixed = ctx.unique_name("sim2real_behav_mixed_").replace("-", "_")
    control = ctx.unique_name("sim2real_behav_ctl_").replace("-", "_")
    mixed_ddl = f'CREATE TABLE {mixed} ("c" INT, "C" INT)'
    ctx.on_cleanup(
        lambda: _describe_sql(
            rsd, cluster_id, f"DROP TABLE IF EXISTS {mixed}", timeout_s=_WARM_STATEMENT_DEADLINE_S
        )
    )
    ctx.on_cleanup(
        lambda: _describe_sql(
            rsd, cluster_id, f"DROP TABLE IF EXISTS {control}",
            timeout_s=_WARM_STATEMENT_DEADLINE_S,
        )
    )

    # Twin positive control on the same wiring: an ordinary DDL that MUST succeed, so "the
    # mixed-case DDL was refused" can be told apart from "every statement is refused".
    _run_sql(rsd, cluster_id, f"CREATE TABLE {control} (a INT)", ctx=ctx)

    shown_before = _show(rsd, cluster_id, ctx=ctx)
    assert _as_bool(shown_before) == _as_bool(baseline_value), (
        f"the engine must report the parameter group's baseline value for {_PARAMETER!r} before "
        f"anything changes: SHOW said {shown_before!r}, the group says {baseline_value!r}"
    )

    refused_before = _describe_sql(rsd, cluster_id, mixed_ddl, ctx=ctx)
    assert refused_before["Status"] == "FAILED", (
        f"with {_PARAMETER}={baseline_value!r} the engine must REFUSE {mixed_ddl!r} as a "
        f"duplicate column, got status={refused_before['Status']!r} "
        f"error={refused_before.get('Error')!r}"
    )
    before_error = refused_before.get("Error") or ""
    assert any(hint in before_error.lower() for hint in _DUPLICATE_HINTS), (
        f"the refusal must be a DUPLICATE-COLUMN failure, not some other error — that is what "
        f"distinguishes case-insensitive identifier folding from a broken cluster; got "
        f"{before_error!r}, expected one of {_DUPLICATE_HINTS!r} in it"
    )

    # ---- the static change lands in the control plane and NOWHERE ELSE yet ----
    _retrying(
        lambda: rs.modify_cluster_parameter_group(
            ParameterGroupName=group_name,
            Parameters=[{"ParameterName": _PARAMETER, "ParameterValue": flipped}],
        )
    )
    after_modify = _stored()[_PARAMETER]
    assert after_modify.get("ParameterValue") == flipped, (
        f"DescribeClusterParameters must report the new value {flipped!r} for {_PARAMETER!r}, "
        f"got {after_modify.get('ParameterValue')!r}"
    )
    # A STATIC change must leave the cluster reporting that it is waiting for a reboot. The poll's
    # terminal set is exactly _AWAITING_REBOOT, so 'in-sync' (the target applied a static change
    # with no reboot) and 'invalid-parameter' (it rejected the value) both time out and RAISE.
    _wait_until(
        _apply_status,
        lambda s: s in _AWAITING_REBOOT,
        timeout_s=_PARAM_STATUS_DEADLINE_S,
        interval_s=2,
        what=(
            f"cluster {cluster_id} to report {group_name} as awaiting a reboot (one of "
            f"{_AWAITING_REBOOT}); 'in-sync' here would mean a static change was applied without "
            f"the reboot AWS requires"
        ),
        ctx=ctx,
    )

    # Three consecutive reads of the same behaviour, so a target that flips it a beat after the
    # modify is caught rather than raced.
    for attempt in range(3):
        frozen = _describe_sql(
            rsd, cluster_id, mixed_ddl, timeout_s=_WARM_STATEMENT_DEADLINE_S, ctx=ctx
        )
        assert frozen["Status"] == "FAILED", (
            f"read {attempt + 1} of 3: {mixed_ddl!r} must still be refused before the reboot — "
            f"the group holds {flipped!r} but the engine has not been restarted — got "
            f"status={frozen['Status']!r} error={frozen.get('Error')!r}"
        )
        frozen_show = _show(rsd, cluster_id, ctx=ctx)
        assert frozen_show == shown_before, (
            f"read {attempt + 1} of 3: SHOW {_PARAMETER} must still report the PRE-change value "
            f"{shown_before!r} until the cluster reboots, got {frozen_show!r}"
        )
    # Second independent observable that the pre-reboot effect is absent: the table the refused
    # DDL would have created does not exist.
    absent = _retrying(
        lambda: rsd.describe_table(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=ADMIN_USERNAME,
            Schema="public", Table=mixed,
        )
    )
    assert absent.get("ColumnList") == [], (
        f"the refused DDL must have created nothing: DescribeTable for {mixed!r} must report an "
        f"EMPTY ColumnList, got {absent.get('ColumnList')!r}"
    )

    # ---- repair ONLY the withheld thing: reboot ----
    _retrying(lambda: rs.reboot_cluster(ClusterIdentifier=cluster_id))
    _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s == "available",
        timeout_s=_REBOOT_DEADLINE_S,
        interval_s=2,
        what=f"cluster {cluster_id} to come back `available` after RebootCluster",
        ctx=ctx,
    )
    _wait_until(
        _apply_status,
        lambda s: s == "in-sync",
        timeout_s=_PARAM_STATUS_DEADLINE_S,
        interval_s=2,
        what=f"parameter group {group_name} to report in-sync after the reboot",
        ctx=ctx,
    )

    shown_after = _show(rsd, cluster_id, ctx=ctx)
    assert _as_bool(shown_after) == _as_bool(flipped), (
        f"after the reboot the ENGINE must report the new value: SHOW {_PARAMETER} said "
        f"{shown_after!r}, expected the equivalent of {flipped!r} (it said {shown_before!r} before)"
    )

    # The identical call that was refused now succeeds, proving the earlier absence was the
    # missing reboot and not a broken cluster.
    _run_sql(rsd, cluster_id, mixed_ddl, timeout_s=_WARM_STATEMENT_DEADLINE_S, ctx=ctx)

    # Terminal assertion: an INDEPENDENT read at the destination, through a different operation
    # (DescribeTable, not the DDL's own response), proving both columns exist with their case
    # preserved — which is only possible if the engine is now case-sensitive.
    described = _retrying(
        lambda: rsd.describe_table(
            ClusterIdentifier=cluster_id, Database=DB_NAME, DbUser=ADMIN_USERNAME,
            Schema="public", Table=mixed,
        )
    )
    names = [column["name"] for column in described["ColumnList"]]
    assert names == ["c", "C"], (
        f"the rebooted engine must preserve identifier case, so {mixed!r} must hold exactly the "
        f"two columns ['c', 'C'] in declaration order; DescribeTable reported {names!r}. A "
        f"single 'c' means the change never reached the engine even after the reboot"
    )

    # And the two columns are genuinely distinct storage, not one column reported twice: writing
    # (1, 2) and reading both back must return both values.
    _run_sql(
        rsd, cluster_id, f"INSERT INTO {mixed} VALUES (1, 2)",
        timeout_s=_WARM_STATEMENT_DEADLINE_S,
        ctx=ctx,
    )
    rows = _select(
        rsd, cluster_id, f'SELECT "c", "C" FROM {mixed}',
        timeout_s=_WARM_STATEMENT_DEADLINE_S,
        ctx=ctx,
    )
    assert [(_cell(r, 0), _cell(r, 1)) for r in rows] == [(1, 2)], (
        f'"c" and "C" must be two distinct columns holding 1 and 2; got {rows!r}. Equal values '
        f"would mean the engine folded them into one column while still accepting the DDL"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
