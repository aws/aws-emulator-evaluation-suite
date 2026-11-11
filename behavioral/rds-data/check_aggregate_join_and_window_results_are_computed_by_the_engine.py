"""aggregate-join-and-window-results-are-computed-by-the-engine."""

from __future__ import annotations

import time
from decimal import Decimal, InvalidOperation

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "aggregate-join-and-window-results-are-computed-by-the-engine"
GROUP = "data-plane"
SERVICES = ["rds-data"]

_DB = "simparitydb"
_USER = "sim2real"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_MEMBER_WAIT_S = 900
_CLUSTER_WAIT_S = 240
_SECRET_WAIT_S = 180
_DATA_API_WAIT_S = 180
_TEARDOWN_WAIT_S = 600
_CLUSTER_RETRY_S = 300
# The member wait, the cluster retry and the subnet-group wait sum to the 1800 s cleanup budget.
_SUBNET_GROUP_WAIT_S = 1800 - _TEARDOWN_WAIT_S - _CLUSTER_RETRY_S

_ORDERS_TABLE = "sim2real_behav_engine_orders"
_CUSTOMERS_TABLE = "sim2real_behav_engine_customers"

# The Field arms a computed result must arrive in.
_NUMERIC_ARM = "stringValue"
_BIGINT_ARM = "longValue"

# Every expected answer is computed from these two lists: 'dora' has an order but no customer row
# (the INNER JOIN drops it), bob's total is below _HAVING_MIN (HAVING removes one group), and the two
# large qty values sum past 2**53 to an odd total that no IEEE-754 double can hold.
_CUSTOMERS = [
    ("alice", "west"),
    ("bob", "east"),
    ("cara", "west"),
]
_ORDERS = [
    (1, "alice", Decimal("10.50"), 4503599627370496),
    (2, "alice", Decimal("20.25"), 4503599627370497),
    (3, "bob", Decimal("5.75"), 1),
    (4, "cara", Decimal("100.00"), 2),
    (5, "cara", Decimal("0.01"), 4),
    (6, "dora", Decimal("999.99"), 5),
]
_HAVING_MIN = Decimal("15")
_AMOUNT_SCALE = 2


def _poll(fn, pred, *, timeout_s, interval_s=15):
    """Poll fn() until pred(value) or the deadline; returns the last value seen."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _instance(rds, inst_id):
    """DescribeDBInstances for one id, or None when it no longer exists."""
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
            return None
        raise


def _cluster(rds, cl_id):
    """DescribeDBClusters for one id, or None when it no longer exists."""
    try:
        return rds.describe_db_clusters(DBClusterIdentifier=cl_id)["DBClusters"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBClusterNotFoundFault":
            return None
        raise


def _delete_instance(rds, inst_id):
    """Delete a cluster member and WAIT for it to vanish. The wait is load-bearing: a cluster
    cannot be deleted while a member remains, so the sibling cleanup registered before this one
    would fail without it."""
    try:
        rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "DBInstanceNotFound":
            raise
    left = _poll(lambda: _instance(rds, inst_id), lambda i: i is None,
                 timeout_s=_TEARDOWN_WAIT_S, interval_s=2)
    if left is not None:
        raise RuntimeError(
            f"cluster member {inst_id} still exists {_TEARDOWN_WAIT_S}s after DeleteDBInstance"
        )


def _delete_cluster(rds, cl_id):
    """Delete the cluster with no final snapshot, retrying while the member drains."""
    deadline = time.monotonic() + _CLUSTER_RETRY_S
    while True:
        try:
            rds.delete_db_cluster(DBClusterIdentifier=cl_id, SkipFinalSnapshot=True)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "DBClusterNotFoundFault":
                return
            if code != "InvalidDBClusterStateFault" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _provision_data_api_cluster(ctx, rds, data):
    """An aurora-postgresql Serverless v2 cluster (0.5 ACU floor) with the Data API on and a managed
    admin-user secret, so the check handles no password; returns (cluster_arn, secret_arn). Cleanups are
    registered cluster first, member second, so teardown deletes the member first."""
    versions = rds.describe_db_engine_versions(
        Engine="aurora-postgresql", DefaultOnly=True
    ).get("DBEngineVersions", [])
    assert versions, (
        "no aurora-postgresql engine version is orderable in "
        f"{ctx.region!r} — the Data API cannot be exercised here"
    )
    version = versions[0]["EngineVersion"]

    cl_id = ctx.unique_name("sim2real-behav-eng-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cl_id,
        Engine="aurora-postgresql",
        EngineVersion=version,
        MasterUsername=_USER,
        ManageMasterUserPassword=True,
        DatabaseName=_DB,
        EnableHttpEndpoint=True,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 4.0},
        BackupRetentionPeriod=1,
        DeletionProtection=False,
        Tags=_MANAGED_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    # Registered FIRST -> torn down LAST, after the member is gone.
    ctx.on_cleanup(lambda: _delete_cluster(rds, cl_id))

    member_id = ctx.unique_name("sim2real-behav-enw-")
    rds.create_db_instance(
        DBInstanceIdentifier=member_id,
        DBClusterIdentifier=cl_id,
        Engine="aurora-postgresql",
        DBInstanceClass="db.serverless",
        Tags=_MANAGED_TAGS,
    )
    # Registered LAST -> torn down FIRST, before the cluster.
    ctx.on_cleanup(lambda: _delete_instance(rds, member_id))

    member = _poll(
        lambda: _instance(rds, member_id),
        lambda i: i is not None and i.get("DBInstanceStatus") == "available",
        timeout_s=_MEMBER_WAIT_S,
    )
    assert member is not None and member.get("DBInstanceStatus") == "available", (
        f"the writer {member_id} did not reach 'available' within {_MEMBER_WAIT_S}s; last status "
        f"{(member or {}).get('DBInstanceStatus')!r}"
    )

    cluster = _poll(
        lambda: _cluster(rds, cl_id),
        lambda c: c is not None and c.get("Status") == "available",
        timeout_s=_CLUSTER_WAIT_S,
    )
    assert cluster is not None and cluster.get("Status") == "available", (
        f"cluster {cl_id} did not reach 'available' within {_CLUSTER_WAIT_S}s; last "
        f"{(cluster or {}).get('Status')!r}"
    )
    assert cluster.get("HttpEndpointEnabled") is True, (
        "the cluster must report HttpEndpointEnabled=True after EnableHttpEndpoint=True; got "
        f"{cluster.get('HttpEndpointEnabled')!r} — the Data API is off and nothing below runs"
    )

    secret_arn = (cluster.get("MasterUserSecret") or {}).get("SecretArn")
    assert secret_arn, (
        "ManageMasterUserPassword must publish MasterUserSecret.SecretArn; the Data API cannot "
        f"authenticate without it (MasterUserSecret={cluster.get('MasterUserSecret')!r})"
    )
    secret_status = _poll(
        lambda: ((_cluster(rds, cl_id) or {}).get("MasterUserSecret") or {}).get("SecretStatus"),
        lambda s: s == "active",
        timeout_s=_SECRET_WAIT_S,
        interval_s=20,
    )
    assert secret_status == "active", (
        f"the managed MasterUserSecret must become 'active' within {_SECRET_WAIT_S}s; it is "
        f"{secret_status!r}"
    )

    cluster_arn = cluster["DBClusterArn"]
    deadline = time.monotonic() + _DATA_API_WAIT_S
    warm = None
    while time.monotonic() < deadline:
        try:
            data.execute_statement(resourceArn=cluster_arn, secretArn=secret_arn,
                                   database=_DB, sql="SELECT 1")
            warm = True
            break
        except ClientError as exc:
            warm = exc
            time.sleep(2)
    assert warm is True, (
        f"the Data API never accepted a trivial statement on {cluster_arn} within "
        f"{_DATA_API_WAIT_S}s; the last refusal was {warm!r}"
    )
    return cluster_arn, secret_arn


def _arm(field, arm, where):
    """The value in the named arm of a Field, failing loudly when the union chose another one."""
    assert isinstance(field, dict) and len(field) == 1, (
        f"{where}: a Field is a tagged union and must carry EXACTLY one arm; got {field!r}"
    )
    assert arm in field, (
        f"{where}: the result must be returned in the {arm!r} arm of the Field union; got "
        f"{field!r} — an emulator that picks a different arm changes the type every caller "
        f"deserialises"
    )
    return field[arm]


def _numeric(field, where) -> Decimal:
    """A computed numeric result, as a Decimal. The ARM is asserted and the TEXT is converted rather
    than compared, so the value assertions in the callers are scale-insensitive and a wrong scale
    hypothesis cannot masquerade as a wrong engine."""
    text = _arm(field, _NUMERIC_ARM, where)
    try:
        return Decimal(text)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise AssertionError(
            f"{where}: the {_NUMERIC_ARM!r} arm of a computed numeric must parse as a decimal "
            f"number; got {text!r}"
        ) from exc


def _expected() -> dict:
    """Every answer this check demands, computed from _CUSTOMERS/_ORDERS, so changing the dataset
    changes every expectation."""
    region_of = dict(_CUSTOMERS)

    totals: dict[str, Decimal] = {}
    for _id, cust, amount, _qty in _ORDERS:
        totals[cust] = totals.get(cust, Decimal(0)) + amount
    having = sorted((c, t) for c, t in totals.items() if t > _HAVING_MIN)

    # INNER JOIN: only orders whose customer exists in _CUSTOMERS.
    joined = [o for o in _ORDERS if o[1] in region_of]
    by_region: dict[str, list] = {}
    for _id, cust, amount, _qty in joined:
        by_region.setdefault(region_of[cust], []).append(amount)
    regions = sorted(
        (r, len(amounts), sum(amounts, Decimal(0))) for r, amounts in by_region.items()
    )

    # ROW_NUMBER() OVER (PARTITION BY cust ORDER BY amount DESC): rank within each customer,
    # highest amount first; the outer ORDER BY is (cust, rn).
    ranked = []
    for cust in sorted(totals):
        rows = sorted((o for o in _ORDERS if o[1] == cust), key=lambda o: o[2], reverse=True)
        for rank, (_id, _c, amount, _qty) in enumerate(rows, start=1):
            ranked.append((cust, amount, rank))

    return {
        "having": having,
        "qty_total": sum(o[3] for o in _ORDERS),
        "regions": regions,
        "ranked": ranked,
        "distinct_customers": len({o[1] for o in _ORDERS}),
        "row_count": len(_ORDERS),
    }


def _grade(data, resource_arn, secret_arn) -> None:
    """Every assertion this check makes, against an already-provisioned Data API cluster."""
    want = _expected()

    def ex(sql, **kw):
        return data.execute_statement(resourceArn=resource_arn, secretArn=secret_arn,
                                      database=_DB, sql=sql, **kw)

    def records(sql):
        resp = ex(sql)
        return resp.get("records") or []

    ex(f"CREATE TABLE {_CUSTOMERS_TABLE} (cust TEXT PRIMARY KEY, region TEXT NOT NULL)")
    ex(f"CREATE TABLE {_ORDERS_TABLE} (id INT PRIMARY KEY, cust TEXT NOT NULL, "
       f"amount NUMERIC(12,{_AMOUNT_SCALE}) NOT NULL, qty BIGINT NOT NULL)")

    # --- The rows are written with BatchExecuteStatement and read back with ExecuteStatement.
    # typeHint=DECIMAL carries the amounts as exact decimal strings, never through a float.
    data.batch_execute_statement(
        resourceArn=resource_arn, secretArn=secret_arn, database=_DB,
        sql=f"INSERT INTO {_CUSTOMERS_TABLE} (cust, region) VALUES (:cust, :region)",
        parameterSets=[
            [{"name": "cust", "value": {"stringValue": cust}},
             {"name": "region", "value": {"stringValue": region}}]
            for cust, region in _CUSTOMERS
        ],
    )
    batch = data.batch_execute_statement(
        resourceArn=resource_arn, secretArn=secret_arn, database=_DB,
        sql=(f"INSERT INTO {_ORDERS_TABLE} (id, cust, amount, qty) "
             f"VALUES (:id, :cust, :amount, :qty)"),
        parameterSets=[
            [{"name": "id", "value": {"longValue": oid}},
             {"name": "cust", "value": {"stringValue": cust}},
             {"name": "amount", "value": {"stringValue": str(amount)}, "typeHint": "DECIMAL"},
             {"name": "qty", "value": {"longValue": qty}}]
            for oid, cust, amount, qty in _ORDERS
        ],
    )
    # Confirms the insert applied; the computed reads below are the verification.
    assert len(batch.get("updateResults") or []) == len(_ORDERS), (
        f"BatchExecuteStatement must report one updateResults entry per parameter set: expected "
        f"{len(_ORDERS)}, got {len(batch.get('updateResults') or [])} in "
        f"{ {k: v for k, v in batch.items() if k != 'ResponseMetadata'} !r}"
    )
    stored = records(f"SELECT count(*) FROM {_ORDERS_TABLE}")
    assert [_arm(r[0], _BIGINT_ARM, "count(*) of the order rows") for r in stored] \
        == [want["row_count"]], (
        f"all {want['row_count']} order rows must be readable through ExecuteStatement after the "
        f"BatchExecuteStatement insert; got {stored!r}"
    )

    # --- Leg A: GROUP BY + SUM(numeric) + HAVING. The engine must add the amounts, group them, and
    # DROP the one group whose total falls below the threshold. The threshold is interpolated from
    # the same constant the Python expectation filters on, so the two cannot drift.
    rows = records(
        f"SELECT cust, SUM(amount) FROM {_ORDERS_TABLE} GROUP BY cust "
        f"HAVING SUM(amount) > {_HAVING_MIN} ORDER BY cust"
    )
    got = [(_arm(r[0], "stringValue", "GROUP BY cust"),
            _numeric(r[1], f"SUM(amount) for {r[0]!r}")) for r in rows]
    assert got == want["having"], (
        f"GROUP BY cust / SUM(amount) / HAVING SUM(amount) > {_HAVING_MIN} must return exactly the "
        f"groups whose summed amounts exceed the threshold, ordered by cust: expected "
        f"{want['having']!r}, got {got!r} — a target that cannot aggregate, cannot group, or "
        f"ignores HAVING answers something else here"
    )
    # The SUM's text keeps the operands' scale; asserted apart from the Decimal comparison above,
    # which ignores scale.
    texts = [_arm(r[1], _NUMERIC_ARM, "SUM(amount) text") for r in rows]
    assert all("." in t and len(t.split(".")[1]) == _AMOUNT_SCALE for t in texts), (
        f"SUM over a NUMERIC(12,{_AMOUNT_SCALE}) column must preserve scale "
        f"{_AMOUNT_SCALE} in the returned text — this is the precision the stringValue arm exists "
        f"to carry; got {texts!r}"
    )

    # --- Leg B: SUM over bigints whose exact total exceeds 2**53. postgres promotes SUM(bigint) to
    # numeric, so the answer arrives as text and must be EXACT. An emulator that accumulates the
    # aggregate in a float64 returns a neighbouring even integer here.
    rows = records(f"SELECT SUM(qty) FROM {_ORDERS_TABLE}")
    assert len(rows) == 1, f"SUM over the whole table must return exactly one row; got {rows!r}"
    qty_total = _numeric(rows[0][0], "SUM(qty)")
    assert qty_total == Decimal(want["qty_total"]), (
        f"SUM(qty) must be the exact integer total of the inserted quantities, "
        f"{want['qty_total']} — which is above 2**53 and odd, so it is NOT representable as an "
        f"IEEE-754 double; got {qty_total} (a target accumulating in float returns a neighbouring "
        f"even value)"
    )

    # --- Leg C: an INNER JOIN across two tables, then GROUP BY the JOINED column. One order's
    # customer is absent from the customers table, so a target that ignores the ON clause,
    # cross-joins, or outer-joins includes her amount and gets a different total.
    rows = records(
        f"SELECT c.region, COUNT(*), SUM(o.amount) FROM {_ORDERS_TABLE} o "
        f"JOIN {_CUSTOMERS_TABLE} c ON c.cust = o.cust GROUP BY c.region ORDER BY c.region"
    )
    got = [(_arm(r[0], "stringValue", "joined region"),
            _arm(r[1], _BIGINT_ARM, f"COUNT(*) for region {r[0]!r}"),
            _numeric(r[2], f"SUM(o.amount) for region {r[0]!r}")) for r in rows]
    assert got == want["regions"], (
        f"an INNER JOIN must drop the order whose customer is absent from "
        f"{_CUSTOMERS_TABLE}, and the per-region counts and sums must be computed over what "
        f"remains: expected {want['regions']!r}, got {got!r}"
    )

    # --- Leg D: a window function. ROW_NUMBER() OVER (PARTITION BY ... ORDER BY ... DESC) is a
    # per-partition ranking that exists only in the result set — there is no column to echo, so
    # nothing but a real engine can produce it.
    rows = records(
        f"SELECT cust, amount, ROW_NUMBER() OVER (PARTITION BY cust ORDER BY amount DESC) AS rn "
        f"FROM {_ORDERS_TABLE} ORDER BY cust, rn"
    )
    got = [(_arm(r[0], "stringValue", "windowed cust"),
            _numeric(r[1], f"windowed amount for {r[0]!r}"),
            _arm(r[2], _BIGINT_ARM, f"ROW_NUMBER() for {r[0]!r}")) for r in rows]
    assert got == want["ranked"], (
        f"ROW_NUMBER() OVER (PARTITION BY cust ORDER BY amount DESC) must rank each customer's "
        f"orders from the largest amount down, restarting at 1 in every partition: expected "
        f"{want['ranked']!r}, got {got!r}"
    )

    # --- Leg E: the terminal read. COUNT(DISTINCT) must deduplicate, so it disagrees with both
    # COUNT(*) and the number of customer rows — the two values a target with no engine has to
    # hand. Deliberately last: it is the cheapest possible aggregate to get wrong.
    rows = records(f"SELECT COUNT(DISTINCT cust) FROM {_ORDERS_TABLE}")
    assert len(rows) == 1, f"COUNT(DISTINCT cust) must return exactly one row; got {rows!r}"
    distinct = _arm(rows[0][0], _BIGINT_ARM, "COUNT(DISTINCT cust)")
    assert distinct == want["distinct_customers"], (
        f"COUNT(DISTINCT cust) must deduplicate to {want['distinct_customers']} — not "
        f"{want['row_count']} (the order count) and not {len(_CUSTOMERS)} (the customers table); "
        f"got {distinct}"
    )


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A grouped SUM with HAVING, an exact SUM above 2**53, an INNER JOIN, a partitioned
    ROW_NUMBER() and a COUNT(DISTINCT) read through ExecuteStatement each equal the value
    computed in Python from the rows the check inserted, so a real SQL engine computed them."""
    rds = ctx.client("rds")
    data = ctx.client("rds-data")
    ctx.client("sts").get_caller_identity()
    resource_arn, secret_arn = _provision_data_api_cluster(ctx, rds, data)
    _grade(data, resource_arn, secret_arn)


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=_SUBNET_GROUP_WAIT_S,
                          interval_s=2.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
