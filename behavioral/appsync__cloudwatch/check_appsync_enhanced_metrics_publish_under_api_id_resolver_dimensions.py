"""appsync-enhanced-metrics-publish-under-api-id-resolver-dimensions."""
from __future__ import annotations

# AWS/AppSync has one api dimension, GraphQLAPIId. Enhanced metrics reuse the transport-level
# names (Requests, Latency, GraphQLError) and add one key: Resolver ("Type.field"), DataSource
# (the data source name) or Operation (the root operation type, not the operationName).

import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "appsync-enhanced-metrics-publish-under-api-id-resolver-dimensions"
GROUP = "observability"
SERVICES = ["appsync", "cloudwatch"]

NAMESPACE = "AWS/AppSync"
API_DIM = "GraphQLAPIId"
SDL = """schema { query: Query }
type Query {
    probe(msg: String!): String
}
"""

JS_ECHO = (
    "export function request(ctx) {\n  return { payload: ctx.args.msg };\n}\n"
    "export function response(ctx) {\n  return ctx.result;\n}\n"
)

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
METRIC_TIMEOUT_S = 900.0
OPERATION_NAME = "EnhancedProbe"
MEASURED_REQUESTS = 3


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout -- never returns its last value."""
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
    """POST JSON with stdlib urllib -> (status, parsed_body). A 4xx/5xx is a RESULT."""
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
    """Every AWS/AppSync metric published for ``api_id`` -- filtered by the ONE real dimension,
    GraphQLAPIId. CloudWatch's ListMetrics dimension filter matches any metric that CARRIES this
    dimension, including ones that also carry a second (Resolver/DataSource/Operation) -- so this
    single query surfaces the whole family, general and enhanced alike (M1, M2).

    Returns a list of (metric_name, {dim: value}). An empty list is a real answer -- the caller's
    positive legs poll for presence and its negative leg feeds this to ``assert not``.
    """
    cw = ctx.client("cloudwatch")
    out = []
    pages = cw.get_paginator("list_metrics").paginate(
        Namespace=NAMESPACE, Dimensions=[{"Name": API_DIM, "Value": api_id}]
    )
    for page in pages:
        for metric in page.get("Metrics", []):
            dims = {d["Name"]: d["Value"] for d in metric.get("Dimensions", [])}
            out.append((metric["MetricName"], dims))
    return out


def _sum_over(ctx, metric_name, dimensions, since):
    """Sum statistic for one metric over the window since ``since``, or None if no datapoints."""
    resp = ctx.client("cloudwatch").get_metric_statistics(
        Namespace=NAMESPACE,
        MetricName=metric_name,
        Dimensions=[{"Name": k, "Value": v} for k, v in dimensions.items()],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=["Sum"],
    )
    points = resp.get("Datapoints") or []
    if not points:
        return None
    return sum(p["Sum"] for p in points)


def _probe_api(ctx, svc, sdl, *, enhanced):
    """A GraphQL API + ACTIVE schema + NONE-backed resolver on Query.probe + api key.

    ``enhanced=False`` builds the twin control: the SAME api in every respect except that it
    declares no enhancedMetricsConfig and its resolver declares no metricsConfig.
    Returns (api_id, uri, key, data_source_name).
    """
    kwargs = dict(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    if enhanced:
        kwargs["enhancedMetricsConfig"] = {
            "resolverLevelMetricsBehavior": "PER_RESOLVER_METRICS",
            "dataSourceLevelMetricsBehavior": "FULL_REQUEST_DATA_SOURCE_METRICS",
            "operationLevelMetricsConfig": "ENABLED",
        }
    api = svc.create_graphql_api(**kwargs)["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    stored = api.get("enhancedMetricsConfig")
    if enhanced:
        assert (stored or {}).get("resolverLevelMetricsBehavior") == "PER_RESOLVER_METRICS", (
            f"CreateGraphqlApi did not store the enhanced metrics config: expected "
            f"PER_RESOLVER_METRICS, got {stored!r}"
        )
    else:
        assert not stored, (
            f"the control api must declare NO enhancedMetricsConfig, got {stored!r}"
        )

    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=180.0, interval_s=2.0,
        description="StartSchemaCreation to reach a terminal status",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation did not succeed: expected SUCCESS/ACTIVE, got {status['status']!r} "
        f"details={status.get('details')!r}"
    )
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"

    ds_name = _alnum(ctx, "ds")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    resolver_kwargs = dict(
        apiId=api_id, typeName="Query", fieldName="probe", kind="UNIT",
        dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_ECHO,
    )
    if enhanced:
        resolver_kwargs["metricsConfig"] = "ENABLED"
    svc.create_resolver(**resolver_kwargs)
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="probe"))
    key = svc.create_api_key(apiId=api_id, description="sim2real-behav metrics key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=key))
    return api_id, uri, key, ds_name


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:metrics", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """Enhanced metrics publish under GraphQLAPIId plus a Resolver ("Type.field"), DataSource (its
    name) or Operation (the root operation type) dimension, while a sibling api without
    enhancedMetricsConfig publishes only the GraphQLAPIId-level metrics for the same traffic."""
    svc = ctx.client("appsync")
    since = datetime.now(timezone.utc) - timedelta(minutes=2)

    on_api, on_url, on_key, on_ds = _probe_api(ctx, svc, SDL, enhanced=True)
    off_api, off_url, off_key, _off_ds = _probe_api(ctx, svc, SDL, enhanced=False)

    marker = ctx.unique_name("metricprobe-")
    document = (
        f"query {OPERATION_NAME}($m: String!) {{ probe(msg: $m) }}"
    )
    expected_operation_dim = document.strip().split(None, 1)[0].capitalize()

    def _ask(url, key):
        return _post_json(
            ctx, url, {"x-api-key": key},
            {"query": document, "operationName": OPERATION_NAME, "variables": {"m": marker}},
        )

    # Both apis are warmed and then driven with the SAME traffic in the same instant.
    for url, key, label in ((on_url, on_key, "enhanced"), (off_url, off_key, "control")):
        _poll_until(
            lambda _u=url, _k=key: _ask(_u, _k),
            lambda res: res[0] == 200 and (res[1].get("data") or {}).get("probe") == marker,
            timeout_s=180.0, interval_s=5.0,
            description=f"the {label} api's resolver to answer on the live endpoint",
        )
    for _ in range(MEASURED_REQUESTS):
        for url, key, label in ((on_url, on_key, "enhanced"), (off_url, off_key, "control")):
            status, body = _ask(url, key)
            assert status == 200 and not body.get("errors"), (
                f"the {label} api stopped serving mid-run: {status!r} {body!r}"
            )

    # ---- the enhanced families, discovered at the consumer -----------------------------------
    enhanced = _poll_until(
        lambda: _metrics_for_api(ctx, on_api),
        lambda found: any(
            name == "Requests" and set(dims) == {API_DIM, "Resolver"} for name, dims in found
        ),
        timeout_s=METRIC_TIMEOUT_S, interval_s=20.0,
        description=(
            f"a Requests metric under {{{API_DIM}, Resolver}} for api {on_api} to be indexed in "
            f"{NAMESPACE}"
        ),
    )

    per_resolver = [d for n, d in enhanced if n == "Requests" and set(d) == {API_DIM, "Resolver"}]
    assert len(per_resolver) == 1, (
        f"expected exactly one per-resolver Requests metric for the single resolver this check "
        f"created, got {len(per_resolver)}: {per_resolver!r}"
    )
    expected_resolver_dim = "Query.probe"
    assert per_resolver[0]["Resolver"] == expected_resolver_dim, (
        f"the Resolver dimension must be exactly typeName.fieldName ({expected_resolver_dim!r}), "
        f"got {per_resolver[0]['Resolver']!r}"
    )

    per_ds = [d for n, d in enhanced if n == "Requests" and set(d) == {API_DIM, "DataSource"}]
    assert per_ds, (
        f"dataSourceLevelMetricsBehavior FULL_REQUEST_DATA_SOURCE_METRICS must publish a Requests "
        f"metric under {{{API_DIM}, DataSource}}; the api published only "
        f"{sorted({(n, tuple(sorted(d))) for n, d in enhanced})!r}"
    )
    assert any(d["DataSource"] == on_ds for d in per_ds), (
        f"the DataSource dimension must name the data source this check created ({on_ds!r}), got "
        f"{[d['DataSource'] for d in per_ds]!r}"
    )

    per_op = [d for n, d in enhanced if n == "Requests" and set(d) == {API_DIM, "Operation"}]
    assert per_op, (
        f"operationLevelMetricsConfig ENABLED must publish a Requests metric under "
        f"{{{API_DIM}, Operation}}; the api published only "
        f"{sorted({(n, tuple(sorted(d))) for n, d in enhanced})!r}"
    )
    assert any(d["Operation"] == expected_operation_dim for d in per_op), (
        f"the Operation dimension must be the GraphQL root operation type "
        f"({expected_operation_dim!r}), got {[d['Operation'] for d in per_op]!r}"
    )

    # ---- the transport-level family, dimensioned by GraphQLAPIId ALONE -----------------------
    general = _poll_until(
        lambda: _metrics_for_api(ctx, on_api),
        lambda found: any(name == "Latency" and set(dims) == {API_DIM} for name, dims in found),
        timeout_s=METRIC_TIMEOUT_S, interval_s=20.0,
        description=f"the transport-level Latency metric under {{{API_DIM}}} for api {on_api}",
    )
    assert any(n == "Latency" and set(d) == {API_DIM} for n, d in general), (
        f"the transport-level Latency metric must be dimensioned by {API_DIM} alone, got "
        f"{[(n, sorted(d)) for n, d in general if n == 'Latency']!r}"
    )

    # ---- the datapoints are real, and at least as many as the traffic we drove ----------------
    total = _poll_until(
        lambda: _sum_over(ctx, "Requests", per_resolver[0], since),
        lambda s: s is not None and s >= MEASURED_REQUESTS,
        timeout_s=METRIC_TIMEOUT_S, interval_s=20.0,
        description=(
            f"the per-resolver Requests metric to accumulate at least the {MEASURED_REQUESTS} "
            f"measured requests"
        ),
    )
    assert total >= MEASURED_REQUESTS, (
        f"expected the per-resolver Requests Sum to be at least the {MEASURED_REQUESTS} requests "
        f"this check drove (warm-up requests may add more), got {total!r}"
    )

    # ---- twin control: no enhancedMetricsConfig means no enhanced-dimensioned metric ----------
    control_general = _poll_until(
        lambda: _metrics_for_api(ctx, off_api),
        lambda found: any(name == "Latency" and set(dims) == {API_DIM} for name, dims in found),
        timeout_s=METRIC_TIMEOUT_S, interval_s=20.0,
        description=(
            f"the control api {off_api} to publish the transport-level Latency metric, proving "
            f"CloudWatch saw its traffic"
        ),
    )
    assert control_general, (
        f"the control api published no metric at all, so its lack of enhanced metrics below "
        f"proves nothing: {control_general!r}"
    )
    control_enhanced = [
        (n, d) for n, d in control_general
        if "Resolver" in d or "DataSource" in d or "Operation" in d
    ]
    assert not control_enhanced, (
        f"an api that declares NO enhancedMetricsConfig must publish no Resolver/DataSource/"
        f"Operation-dimensioned metric, yet {off_api} published {control_enhanced!r} -- and "
        f"indexing on this wiring is demonstrably current because the enabled api's per-resolver "
        f"metric was found and its transport-level metric is present too"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
