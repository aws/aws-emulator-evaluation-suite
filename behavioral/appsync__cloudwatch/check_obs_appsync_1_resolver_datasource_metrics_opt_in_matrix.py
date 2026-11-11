"""obs-appsync-1-resolver-datasource-metrics-opt-in-matrix."""
from __future__ import annotations

# The only api-id dimension in AWS/AppSync is GraphQLAPIId; enhanced metrics reuse the names
# Requests / Latency / GraphQLError and add one key (Resolver | DataSource | Operation). The
# Resolver value is f"{typeName}.{fieldName}"; the Operation value is the root operation type.
#
# Enhanced Requests and GraphQLError datapoints are stored with Unit "None"; a Unit="Count" query
# returns no datapoints at all.

import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "obs-appsync-1-resolver-datasource-metrics-opt-in-matrix"
GROUP = "observability"
SERVICES = ["appsync", "cloudwatch"]

NAMESPACE = "AWS/AppSync"
API_DIM = "GraphQLAPIId"
METRIC_TIMEOUT_S = 900.0
METRIC_INTERVAL_S = 20.0

A_CALLS = 3          # requests against Query.a (resolver ENABLED, data source ENABLED)
B_CALLS = 3          # requests against Query.b (resolver DISABLED, data source DISABLED)
C_FAIL_CALLS = 2     # Query.c requests whose resolver calls util.error(...)
C_OK_CALLS = 1       # Query.c requests that succeed
ERROR_TYPE = "Sim2RealInjected"
STORED_UNIT = "None"  # see the unit note at the top of the file

SDL = """schema { query: Query }
type Query {
    a(m: String!): String
    b(m: String!): String
    c(m: String!, fail: Boolean!): String
}
"""

JS_ECHO = (
    "export function request(ctx) {\n  return { payload: ctx.args.m };\n}\n"
    "export function response(ctx) {\n  return ctx.result;\n}\n"
)

JS_MAYBE_FAIL = (
    "import { util } from '@aws-appsync/utils';\n"
    "export function request(ctx) {\n"
    "  if (ctx.args.fail) {\n"
    f"    util.error('sim2real injected failure', '{ERROR_TYPE}');\n"
    "  }\n"
    "  return { payload: ctx.args.m };\n"
    "}\n"
    "export function response(ctx) {\n  return ctx.result;\n}\n"
)

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0, description="condition"):
    """Poll probe() until predicate holds; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _alnum(ctx, prefix):
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_json(ctx, url, headers, payload, timeout_s=30):
    """POST JSON with stdlib urllib -> (status, parsed_body); a 4xx/5xx is returned, not raised."""
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", **headers, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, {"transport_error": str(exc)}
    try:
        return status, (json.loads(raw) if raw else {})
    except ValueError:
        return status, {"raw": raw}


def _metrics_for_api(ctx, api_id):
    """Every AWS/AppSync catalogue entry carrying GraphQLAPIId=api_id -> [(name, {dim: value})].

    The ListMetrics dimension filter matches any metric that CARRIES the dimension, including ones
    that also carry Resolver/DataSource/Operation, so one paginated query sees the whole family.
    """
    out = []
    pages = ctx.client("cloudwatch").get_paginator("list_metrics").paginate(
        Namespace=NAMESPACE, Dimensions=[{"Name": API_DIM, "Value": api_id}]
    )
    for page in pages:
        for metric in page.get("Metrics", []):
            out.append((metric["MetricName"],
                        {d["Name"]: d["Value"] for d in metric.get("Dimensions", [])}))
    return out


def _datapoints(ctx, metric_name, dimensions, since, unit=None):
    """Sum datapoints (Period=60) for one metric with EXACTLY ``dimensions`` since ``since``."""
    kwargs = {"Unit": unit} if unit else {}
    resp = ctx.client("cloudwatch").get_metric_statistics(
        Namespace=NAMESPACE,
        MetricName=metric_name,
        Dimensions=[{"Name": k, "Value": v} for k, v in dimensions.items()],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=["Sum"],
        **kwargs,
    )
    return resp.get("Datapoints") or []


def _units(points):
    return {p.get("Unit") for p in points}


def _total(points):
    return sum(p["Sum"] for p in points)


def _align_to_fresh_minute(margin_s=5.0):
    """Wait out the current CloudWatch minute bucket and return the start of a fresh one.

    Period=60 datapoints are bucketed on the minute, so this window excludes warm-up traffic.
    """
    now = time.time()
    boundary = (int(now // 60) + 1) * 60
    if boundary - now < margin_s:
        boundary += 60
    time.sleep(max(0.0, boundary + margin_s - time.time()))
    return datetime.fromtimestamp(boundary, timezone.utc)


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/appsync/latest/devguide/monitoring.html
@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:metrics",
      "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Per-resolver and per-data-source metricsConfig opt-ins decide which AppSync dimension sets
    CloudWatch publishes, with exact Sums. FULL_REQUEST_RESOLVER_METRICS later overrides the
    resolver opt-out, while the opted-out data source stays absent.

    Reference: https://docs.aws.amazon.com/appsync/latest/devguide/monitoring.html
    """
    svc = ctx.client("appsync")

    api_name = ctx.unique_name("sim2real-xsvc-appsync-metrics-")
    initial_cfg = {
        "resolverLevelMetricsBehavior": "PER_RESOLVER_METRICS",
        "dataSourceLevelMetricsBehavior": "PER_DATA_SOURCE_METRICS",
        "operationLevelMetricsConfig": "DISABLED",
    }
    api = svc.create_graphql_api(
        name=api_name, authenticationType="API_KEY", enhancedMetricsConfig=initial_cfg,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    assert api.get("enhancedMetricsConfig") == initial_cfg, (
        f"CreateGraphqlApi must store the enhancedMetricsConfig verbatim: expected "
        f"{initial_cfg!r}, got {api.get('enhancedMetricsConfig')!r}"
    )
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"

    svc.start_schema_creation(apiId=api_id, definition=SDL.encode("utf-8"))
    status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=180.0, interval_s=2.0,
        description="StartSchemaCreation to reach a terminal status",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation did not succeed: got {status['status']!r} "
        f"details={status.get('details')!r}"
    )

    # Two NONE data sources: one opted in, one opted out.
    ds_on = _alnum(ctx, "dson")
    ds_off = _alnum(ctx, "dsoff")
    for ds_name, cfg in ((ds_on, "ENABLED"), (ds_off, "DISABLED")):
        created = svc.create_data_source(
            apiId=api_id, name=ds_name, type="NONE", metricsConfig=cfg)["dataSource"]
        ctx.on_cleanup(lambda _n=ds_name: svc.delete_data_source(apiId=api_id, name=_n))
        assert created.get("metricsConfig") == cfg, (
            f"CreateDataSource must store metricsConfig={cfg!r} on {ds_name!r}, "
            f"got {created.get('metricsConfig')!r}"
        )

    for field, ds_name, cfg, code in (
        ("a", ds_on, "ENABLED", JS_ECHO),
        ("b", ds_off, "DISABLED", JS_ECHO),
        ("c", ds_on, "ENABLED", JS_MAYBE_FAIL),
    ):
        created = svc.create_resolver(
            apiId=api_id, typeName="Query", fieldName=field, kind="UNIT",
            dataSourceName=ds_name, runtime=APPSYNC_JS, code=code, metricsConfig=cfg,
        )["resolver"]
        ctx.on_cleanup(lambda _f=field: svc.delete_resolver(
            apiId=api_id, typeName="Query", fieldName=_f))
        assert created.get("metricsConfig") == cfg, (
            f"CreateResolver must store metricsConfig={cfg!r} on Query.{field}, "
            f"got {created.get('metricsConfig')!r}"
        )

    key = svc.create_api_key(apiId=api_id, description="sim2real-xsvc metrics key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=key))

    marker = ctx.unique_name("m-")

    def _ask(field, fail=None):
        if field == "c":
            doc = "query Q($m: String!, $f: Boolean!) { c(m: $m, fail: $f) }"
            variables = {"m": marker, "f": bool(fail)}
        else:
            doc = f"query Q($m: String!) {{ {field}(m: $m) }}"
            variables = {"m": marker}
        return _post_json(ctx, uri, {"x-api-key": key}, {"query": doc, "variables": variables})

    def _ok(res, field):
        return res[0] == 200 and not res[1].get("errors") and \
            (res[1].get("data") or {}).get(field) == marker

    def _failed(res):
        errs = res[1].get("errors") or []
        return res[0] == 200 and len(errs) == 1 and errs[0].get("errorType") == ERROR_TYPE \
            and (res[1].get("data") or {}).get("c") is None

    # Warm-up: every path answers before the counted window starts.
    for field in ("a", "b", "c"):
        _poll_until(
            lambda _f=field: _ask(_f, fail=False),
            lambda res, _f=field: _ok(res, _f),
            timeout_s=180.0, interval_s=5.0,
            description=f"Query.{field} to answer on the live GraphQL endpoint",
        )
    warm_fail = _ask("c", fail=True)
    assert _failed(warm_fail), (
        f"Query.c with fail=true must return exactly one GraphQL error of type {ERROR_TYPE!r} and "
        f"a null field, got {warm_fail!r}"
    )

    since = _align_to_fresh_minute()

    # a and b are interleaved, so once a's Sum lands, b's would have too.
    for _ in range(max(A_CALLS, B_CALLS)):
        for field, n in (("a", A_CALLS), ("b", B_CALLS)):
            if n:
                res = _ask(field)
                assert _ok(res, field), f"Query.{field} stopped serving mid-run: {res!r}"
    for i in range(C_FAIL_CALLS + C_OK_CALLS):
        fail = i < C_FAIL_CALLS
        res = _ask("c", fail=fail)
        if fail:
            assert _failed(res), f"a failing Query.c call must carry one {ERROR_TYPE!r} error: {res!r}"
        else:
            assert _ok(res, "c"), f"a succeeding Query.c call must return the marker: {res!r}"

    res_a = {API_DIM: api_id, "Resolver": "Query.a"}
    res_b = {API_DIM: api_id, "Resolver": "Query.b"}
    res_c = {API_DIM: api_id, "Resolver": "Query.c"}
    dsd_on = {API_DIM: api_id, "DataSource": ds_on}
    dsd_off = {API_DIM: api_id, "DataSource": ds_off}
    op_query = {API_DIM: api_id, "Operation": "Query"}

    a_points = _poll_until(
        lambda: _datapoints(ctx, "Requests", res_a, since),
        lambda pts: _total(pts) >= A_CALLS,
        timeout_s=METRIC_TIMEOUT_S, interval_s=METRIC_INTERVAL_S,
        description=f"Requests under {res_a!r} to accumulate {A_CALLS} measured requests",
    )
    assert _total(a_points) == A_CALLS, (
        f"Requests Sum under {res_a!r} since {since.isoformat()} must equal the {A_CALLS} measured "
        f"requests EXACTLY (warm-up traffic precedes the window), got {_total(a_points)!r} "
        f"from {a_points!r}"
    )
    assert _units(a_points) == {STORED_UNIT}, (
        f"Requests is published with Unit={STORED_UNIT!r} on real AWS, got {_units(a_points)!r}"
    )
    as_count = _datapoints(ctx, "Requests", res_a, since, unit="Count")
    assert not as_count, (
        f"Requests is stored with Unit={STORED_UNIT!r}, so a Unit=Count read must return no "
        f"datapoints, got {as_count!r}"
    )

    c_err_points = _poll_until(
        lambda: _datapoints(ctx, "GraphQLError", res_c, since),
        lambda pts: _total(pts) >= C_FAIL_CALLS,
        timeout_s=METRIC_TIMEOUT_S, interval_s=METRIC_INTERVAL_S,
        description=f"GraphQLError under {res_c!r} to accumulate {C_FAIL_CALLS} failures",
    )
    assert _total(c_err_points) == C_FAIL_CALLS, (
        f"GraphQLError Sum under {res_c!r} must equal the {C_FAIL_CALLS} util.error calls "
        f"exactly, got {_total(c_err_points)!r} from {c_err_points!r}"
    )
    assert _units(c_err_points) == {STORED_UNIT}, (
        f"GraphQLError is published with Unit={STORED_UNIT!r} on real AWS, "
        f"got {_units(c_err_points)!r}"
    )

    catalogue = _poll_until(
        lambda: _metrics_for_api(ctx, api_id),
        lambda found: ("Requests", res_a) in found and ("Requests", dsd_on) in found,
        timeout_s=METRIC_TIMEOUT_S, interval_s=METRIC_INTERVAL_S,
        description=(
            f"ListMetrics to carry Requests under exactly {res_a!r} and {dsd_on!r}"
        ),
    )
    a_entries = [d for n, d in catalogue if n == "Requests" and d.get("Resolver") == "Query.a"]
    assert a_entries == [res_a], (
        f"Query.a's Requests metric must exist under EXACTLY {{GraphQLAPIId, Resolver}}, "
        f"got {a_entries!r}"
    )

    # Barrier: a's interleaved traffic has landed exactly and is indexed, so b's would have too.
    for dims, what in ((res_b, "resolver Query.b (metricsConfig DISABLED)"),
                       (dsd_off, f"data source {ds_off} (metricsConfig DISABLED)"),
                       (op_query, "operation level (operationLevelMetricsConfig DISABLED)")):
        pts = _datapoints(ctx, "Requests", dims, since)
        assert not pts, (
            f"{what} must publish no Requests datapoints under PER_* behaviour, yet {dims!r} "
            f"carries {pts!r} while Query.a's interleaved traffic already landed exactly"
        )
    leaked = [(n, d) for n, d in catalogue
              if d.get("Resolver") == "Query.b" or d.get("DataSource") == ds_off
              or "Operation" in d]
    assert not leaked, (
        f"opted-out dimensions must never be catalogued, yet ListMetrics for api {api_id} "
        f"carries {leaked!r}"
    )

    # FULL_REQUEST_RESOLVER_METRICS overrides the per-resolver opt-out.
    full_cfg = dict(initial_cfg, resolverLevelMetricsBehavior="FULL_REQUEST_RESOLVER_METRICS")
    updated = svc.update_graphql_api(
        apiId=api_id, name=api_name, authenticationType="API_KEY", enhancedMetricsConfig=full_cfg,
    )["graphqlApi"]
    assert updated.get("enhancedMetricsConfig") == full_cfg, (
        f"UpdateGraphqlApi must store {full_cfg!r}, got {updated.get('enhancedMetricsConfig')!r}"
    )

    def _drive_b_then_read():
        res = _ask("b")
        assert _ok(res, "b"), f"Query.b stopped serving after UpdateGraphqlApi: {res!r}"
        return _datapoints(ctx, "Requests", res_b, since)

    b_points = _poll_until(
        _drive_b_then_read,
        lambda pts: _total(pts) > 0,
        timeout_s=METRIC_TIMEOUT_S, interval_s=METRIC_INTERVAL_S,
        description=(
            f"Requests under {res_b!r} to appear once FULL_REQUEST_RESOLVER_METRICS overrides "
            f"Query.b's metricsConfig=DISABLED"
        ),
    )
    assert _units(b_points) == {STORED_UNIT}, (
        f"Query.b's Requests must carry Unit={STORED_UNIT!r}, got {_units(b_points)!r}"
    )
    catalogue2 = _poll_until(
        lambda: _metrics_for_api(ctx, api_id),
        lambda found: ("Requests", res_b) in found,
        timeout_s=METRIC_TIMEOUT_S, interval_s=METRIC_INTERVAL_S,
        description=f"ListMetrics to catalogue Requests under {res_b!r} after the update",
    )
    # The data-source behaviour did not change, so ds_off -- which served every Query.b call that
    # just became visible -- must STILL publish nothing.
    off_pts = _datapoints(ctx, "Requests", dsd_off, since)
    assert not off_pts, (
        f"data source {ds_off} is still metricsConfig DISABLED under PER_DATA_SOURCE_METRICS, yet "
        f"it published {off_pts!r} once Query.b's resolver metrics became visible"
    )
    still_leaked = [(n, d) for n, d in catalogue2
                    if d.get("DataSource") == ds_off or "Operation" in d]
    assert not still_leaked, (
        f"after enabling FULL_REQUEST_RESOLVER_METRICS only resolver-level metrics may change, "
        f"yet ListMetrics carries {still_leaked!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
