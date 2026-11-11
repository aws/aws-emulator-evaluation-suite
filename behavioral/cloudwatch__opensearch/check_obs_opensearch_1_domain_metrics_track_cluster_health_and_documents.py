"""obs-opensearch-1-domain-metrics-track-cluster-health-and-documents."""
from __future__ import annotations

import datetime
import json
import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "obs-opensearch-1-domain-metrics-track-cluster-health-and-documents"
GROUP = 'metrics'
SERVICES = ['cloudwatch', 'opensearch']

ENGINE_VERSION = "OpenSearch_2.11"
CLUSTER_CONFIG = {"InstanceType": "t3.small.search", "InstanceCount": 1}
EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}

NAMESPACE = "AWS/ES"
REQUIRED_METRICS = (
    "ClusterStatus.green", "ClusterStatus.yellow", "ClusterStatus.red",
    "Nodes", "SearchableDocuments",
)
N_DOCS = 25
M_SEARCHES = 20
POLL_DEADLINE_S = 600
#: How long a fresh domain's data-plane authorizer may take to admit the access policy.
DATA_PLANE_READY_S = 300.0
POLL_STEP_S = 2.0

# An endpoint data-plane FAIL marker: a check detail containing this string is classified as a
# real fidelity failure, ahead of a connection-error or not-implemented classification.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


# ===== helpers (self-contained) =====

def _signed(ctx, method: str, url: str, body: bytes | None = None,
            content_type: str = "application/json"):
    """Send a SigV4-signed ('es') HTTPS request to the domain endpoint; return (status, json).

    Signs with botocore and sends with stdlib urllib, so no third-party HTTP client is needed.
    Signs with the credentials ctx wired for THIS (leased) account, never boto3's ambient chain:
    the domain's access policy is scoped to the caller account's root.
    """
    import urllib.error
    import urllib.request

    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()
    headers = {"Content-Type": content_type} if body is not None else {}
    aws_req = AWSRequest(method=method, url=url, data=body, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)
    req = urllib.request.Request(url, data=body, method=method, headers=dict(aws_req.headers))
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"raw": raw}
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # the endpoint did not answer
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} {url} did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _delete_domain(osc, domain_name: str) -> None:
    """DeleteDomain, done when the domain is already gone."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _json_body(obj) -> bytes:
    return json.dumps(obj).encode()


def _access_policy(account_id: str, region: str, domain_name: str) -> str:
    arn = f"arn:aws:es:{region}:{account_id}:domain/{domain_name}"
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"{arn}/*",
        }],
    })


def _cap_s(ctx, timeout_s: float) -> float:
    """A wait's timeout bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0))


def _not_graded(start: float, timeout_s: float, what: str) -> TimeoutError:
    """A wait the runner's budget cut short: no verdict."""
    return TimeoutError(
        f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
        f"{timeout_s:.0f}s wait for {what} ended; not graded"
    )


def _wait_domain_searchable(ctx, osc, domain_name: str, timeout_s: float = 1500) -> str:
    start = time.monotonic()
    cap_s = _cap_s(ctx, timeout_s)
    last = None
    while time.monotonic() - start < cap_s:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(POLL_STEP_S)
    if cap_s < timeout_s:
        raise _not_graded(start, timeout_s, f"domain {domain_name} to be searchable")
    detail = (f"domain {domain_name} never became searchable within {timeout_s}s "
              f"(last Processing={last.get('Processing') if last else '?'}, "
              f"Endpoint={last.get('Endpoint') if last else '?'})")
    raise AssertionError(detail)


def _next_minute(t: datetime.datetime) -> datetime.datetime:
    """The first whole-minute boundary strictly after `t`: a 60 s datapoint stamped here was
    aggregated entirely after `t`, so its Maximum cannot carry the pre-transition state."""
    return t.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)


def _this_minute(t: datetime.datetime) -> datetime.datetime:
    return t.replace(second=0, microsecond=0)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _domain_dims(account_id: str, domain_name: str) -> list[dict]:
    return [{"Name": "ClientId", "Value": account_id},
            {"Name": "DomainName", "Value": domain_name}]


def _series(cw, account_id: str, domain_name: str, names, start, stat: str = "Maximum") -> dict:
    """{metric_name: {timestamp: value}} for the domain-level series, period 60, paginated."""
    queries = [{
        "Id": f"m{i}",
        "MetricStat": {
            "Metric": {"Namespace": NAMESPACE, "MetricName": n,
                       "Dimensions": _domain_dims(account_id, domain_name)},
            "Period": 60, "Stat": stat,
        },
        "ReturnData": True,
    } for i, n in enumerate(names)]
    out: dict = {n: {} for n in names}
    token = None
    while True:
        kw = dict(MetricDataQueries=queries, StartTime=start,
                  EndTime=_now() + datetime.timedelta(minutes=2), ScanBy="TimestampAscending")
        if token:
            kw["NextToken"] = token
        resp = cw.get_metric_data(**kw)
        for res in resp["MetricDataResults"]:
            name = names[int(res["Id"][1:])]
            for ts, val in zip(res["Timestamps"], res["Values"]):
                out[name][ts] = val
        token = resp.get("NextToken")
        if not token:
            return out


def _poll_metrics(ctx, cw, account_id, domain_name, names, start, matches, label, stat="Maximum"):
    """Poll GetMetricData until some timestamp >= `start` satisfies `matches(series, ts)`.

    Two-sided: a datapoint stamped before `start` is never accepted (it may carry the state from
    before the transition), and the wait is bounded by POLL_DEADLINE_S. Returns (ts, series).
    """
    began = time.monotonic()
    cap_s = _cap_s(ctx, POLL_DEADLINE_S)
    series: dict = {}
    while True:
        series = _series(cw, account_id, domain_name, names, start - datetime.timedelta(minutes=5),
                         stat=stat)
        stamps = sorted({ts for n in names for ts in series[n] if ts >= start})
        for ts in stamps:
            if matches(series, ts):
                return ts, series
        if time.monotonic() - began >= cap_s:
            break
        time.sleep(POLL_STEP_S)
    if cap_s < POLL_DEADLINE_S:
        raise _not_graded(began, POLL_DEADLINE_S, label)
    printable = {n: {ts.isoformat(): v for ts, v in sorted(series.get(n, {}).items())}
                 for n in names}
    raise AssertionError(
        f"{label}: no {stat} datapoint at or after {start.isoformat()} satisfied the expected "
        f"state within {POLL_DEADLINE_S}s; observed series {printable!r}"
    )


def _health(ctx, base: str) -> dict:
    status, body = _signed(ctx, "GET", f"{base}/_cluster/health")
    assert status == 200, f"_cluster/health returned HTTP {status}: {body!r}"
    return body


def _wait_health(ctx, base: str, want: str, timeout_s: float = 120) -> dict:
    start = time.monotonic()
    cap_s = _cap_s(ctx, timeout_s)
    body = _health(ctx, base)
    while body.get("status") != want and time.monotonic() - start < cap_s:
        time.sleep(POLL_STEP_S)
        body = _health(ctx, base)
    if body.get("status") != want and cap_s < timeout_s:
        raise _not_graded(start, timeout_s, f"_cluster/health {want!r}")
    assert body.get("status") == want, (
        f"_cluster/health never reported {want!r} within {timeout_s}s; last body {body!r}"
    )
    return body


# ===== end helpers =====


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-cloudwatchmetrics.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:metrics", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A single-node OpenSearch domain's data-plane acts surface as exact AWS/ES metrics.

    An unplaceable replica turns ClusterStatus yellow, and a `_bulk` of N documents adds
    exactly N to SearchableDocuments, under exactly the {ClientId, DomainName} dimension set and no other.
    """
    osc = ctx.client("opensearch")
    cw = ctx.client("cloudwatch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Bounded startup jitter, not a wait for any condition: CreateDomain is throttled per account
    # and other suites provision domains too. No assertion below depends on this delay's length.
    time.sleep(random.uniform(0, 10.0))
    domain_name = ctx.unique_name("sim2real-xsvc-cwos-")[:28].rstrip("-")
    for attempt in range(12):
        try:
            osc.create_domain(
                DomainName=domain_name,
                EngineVersion=ENGINE_VERSION,
                ClusterConfig=dict(CLUSTER_CONFIG),
                EBSOptions=dict(EBS_OPTIONS),
                AccessPolicies=_access_policy(account_id, ctx.region, domain_name),
                TagList=[{"Key": "sim2real:managed", "Value": "true"},
                         {"Key": "sim2real", "Value": CHECK}],
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError("CreateDomain still throttled after 12 attempts")
    ctx.on_cleanup(lambda: _delete_domain(osc, domain_name))

    endpoint = _wait_domain_searchable(ctx, osc, domain_name)
    base = ctx.endpoint_url(endpoint)
    # A published Endpoint does not mean the data-plane authorizer has the access policy yet.
    dp_start = time.monotonic()
    dp_cap_s = _cap_s(ctx, DATA_PLANE_READY_S)
    while True:
        st, body = _signed(ctx, "GET", f"{base}/")
        if st == 200 or time.monotonic() - dp_start >= dp_cap_s:
            break
        time.sleep(POLL_STEP_S)
    if st != 200 and dp_cap_s < DATA_PLANE_READY_S:
        raise _not_graded(dp_start, DATA_PLANE_READY_S, "the domain's data plane to answer")
    assert st == 200, f"signed GET / on the domain endpoint never returned 200: {st} {body!r}"

    # Index A (replicas=0) is created before the catalogue wait so phase (2a)'s gate minute
    # passes while ListMetrics catches up; nothing in (1) depends on it.
    index_a = ctx.unique_name("sim2real-health-")
    st, body = _signed(ctx, "PUT", f"{base}/{index_a}", _json_body(
        {"settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}}}))
    assert st == 200 and body.get("acknowledged") is True, (
        f"creating index {index_a} with 0 replicas failed: HTTP {st} {body!r}"
    )
    # Index B (the document index) is created now, empty, so that by the time the SearchableDocuments
    # baseline is read in (3) nothing about index creation can still be moving that metric.
    index_b = ctx.unique_name("sim2real-docs-")
    st, body = _signed(ctx, "PUT", f"{base}/{index_b}", _json_body(
        {"settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}}}))
    assert st == 200 and body.get("acknowledged") is True, (
        f"creating index {index_b} failed: HTTP {st} {body!r}"
    )
    green_body = _wait_health(ctx, base, "green")
    assert green_body.get("number_of_nodes") == 1, (
        f"_cluster/health number_of_nodes was {green_body.get('number_of_nodes')!r}, expected 1"
    )
    t_green = _now()

    # ---- (1) the metric catalogue: AWS/ES, exactly {ClientId, DomainName}, nowhere else ----
    cat_start = time.monotonic()
    cat_cap_s = _cap_s(ctx, POLL_DEADLINE_S)
    while True:
        listed = []
        for page in cw.get_paginator("list_metrics").paginate(
                Namespace=NAMESPACE,
                Dimensions=[{"Name": "DomainName", "Value": domain_name}]):
            listed.extend(page["Metrics"])
        names_listed = {m["MetricName"] for m in listed}
        if set(REQUIRED_METRICS) <= names_listed or time.monotonic() - cat_start >= cat_cap_s:
            break
        time.sleep(POLL_STEP_S)
    missing = sorted(set(REQUIRED_METRICS) - names_listed)
    if missing and cat_cap_s < POLL_DEADLINE_S:
        raise _not_graded(cat_start, POLL_DEADLINE_S, "the AWS/ES metric catalogue")
    assert not missing, (
        f"ListMetrics({NAMESPACE}, DomainName={domain_name}) never listed {missing!r} within "
        f"{POLL_DEADLINE_S}s; listed {sorted(names_listed)!r}"
    )
    want_dims = {"ClientId": account_id, "DomainName": domain_name}
    for name in REQUIRED_METRICS:
        dim_sets = [{d["Name"]: d["Value"] for d in m["Dimensions"]}
                    for m in listed if m["MetricName"] == name]
        assert dim_sets == [want_dims], (
            f"{name} is listed with dimension sets {dim_sets!r}; expected exactly one, "
            f"{want_dims!r}"
        )
    other = []
    for page in cw.get_paginator("list_metrics").paginate(
            Namespace="AWS/OpenSearchService",
            Dimensions=[{"Name": "DomainName", "Value": domain_name}]):
        other.extend(page["Metrics"])
    assert other == [], (
        f"domain {domain_name} metrics appeared under AWS/OpenSearchService, which AWS does not "
        f"publish to: {[m['MetricName'] for m in other]!r}"
    )

    status_names = ["ClusterStatus.green", "ClusterStatus.yellow", "ClusterStatus.red"]

    def _state(green: float, yellow: float, red: float):
        def matches(series, ts):
            vals = [series[n].get(ts) for n in status_names]
            return vals == [green, yellow, red]
        return matches

    # ---- (2a) replicas=0 on a one-node cluster: green==1, yellow==0, red==0 ----
    ts_green, _ = _poll_metrics(ctx, cw, account_id, domain_name, status_names, _next_minute(t_green),
                                _state(1.0, 0.0, 0.0), "replicas=0 -> ClusterStatus green")

    # ---- (2b) replicas=1 on the same one-node cluster: the replica cannot be placed -> yellow ----
    st, body = _signed(ctx, "PUT", f"{base}/{index_a}/_settings", _json_body(
        {"index": {"number_of_replicas": 1}}))
    assert st == 200 and body.get("acknowledged") is True, (
        f"raising {index_a} to 1 replica failed: HTTP {st} {body!r}"
    )
    yellow_body = _wait_health(ctx, base, "yellow")
    assert yellow_body.get("unassigned_shards", 0) >= 1, (
        f"cluster is yellow but reports no unassigned shard: {yellow_body!r}"
    )
    t_yellow = _now()
    ts_yellow, _ = _poll_metrics(ctx, cw, account_id, domain_name, status_names, _next_minute(t_yellow),
                                 _state(0.0, 1.0, 0.0), "replicas=1 -> ClusterStatus yellow")
    assert ts_yellow > ts_green, (
        f"yellow datapoint {ts_yellow.isoformat()} does not follow green {ts_green.isoformat()}"
    )

    # Back to green so the document phase below is graded on a healthy cluster.
    st, body = _signed(ctx, "PUT", f"{base}/{index_a}/_settings", _json_body(
        {"index": {"number_of_replicas": 0}}))
    assert st == 200 and body.get("acknowledged") is True, (
        f"lowering {index_a} back to 0 replicas failed: HTTP {st} {body!r}"
    )
    _wait_health(ctx, base, "green")

    # ---- (3) _bulk N docs, refresh, M searches -> SearchableDocuments, Nodes, SearchRate ----
    # SearchableDocuments is NOT the data plane's _stats total: measured on a fresh 2.11 domain it
    # read 2 while _stats/docs (expand_wildcards=all) counted 453, because the service leaves some
    # system indices out. So the exact claim is the DELTA: the last datapoint sampled wholly before
    # the _bulk, plus N, is what the first datapoint sampled wholly after it must read.
    # The service's own indices can still add a document or two after the domain turns green,
    # so the baseline is a settled one: two consecutive minutes, both sampled after this point,
    # reading the same count. The _bulk follows at once.
    t_settle = _now()
    settle_start = time.monotonic()
    settle_cap_s = _cap_s(ctx, POLL_DEADLINE_S)
    while True:
        before = _series(cw, account_id, domain_name, ["SearchableDocuments"],
                         t_green - datetime.timedelta(minutes=5))["SearchableDocuments"]
        pre = sorted(ts for ts in before if ts >= _next_minute(t_settle))
        if len(pre) >= 2 and pre[-1] - pre[-2] == datetime.timedelta(minutes=1) and (
                before[pre[-1]] == before[pre[-2]]):
            break
        if time.monotonic() - settle_start >= settle_cap_s:
            if settle_cap_s < POLL_DEADLINE_S:
                raise _not_graded(settle_start, POLL_DEADLINE_S, "a settled SearchableDocuments")
            raise AssertionError(
                f"SearchableDocuments never read the same count in two consecutive minutes after "
                f"{_next_minute(t_settle).isoformat()} within {POLL_DEADLINE_S}s, so no pre-_bulk "
                f"baseline exists: {({ts.isoformat(): v for ts, v in sorted(before.items())})!r}"
            )
        time.sleep(POLL_STEP_S)
    baseline = before[pre[-1]]
    ndjson = "".join(
        json.dumps({"index": {"_index": index_b, "_id": str(i)}}) + "\n"
        + json.dumps({"n": i, "kind": "sim2real", "marker": domain_name}) + "\n"
        for i in range(N_DOCS)
    ).encode()
    st, body = _signed(ctx, "POST", f"{base}/_bulk?refresh=true", ndjson,
                       content_type="application/x-ndjson")
    assert st == 200 and body.get("errors") is False, f"_bulk failed: HTTP {st} {body!r}"
    created = [it["index"]["status"] for it in body.get("items", [])]
    assert created == [201] * N_DOCS, f"_bulk item statuses were {created!r}, expected 25x 201"
    st, body = _signed(ctx, "GET", f"{base}/{index_b}/_count")
    assert st == 200 and body.get("count") == N_DOCS, (
        f"_count on {index_b} returned HTTP {st} {body!r}, expected count {N_DOCS}"
    )
    t_docs = _now()

    t_search = _now()
    for i in range(M_SEARCHES):
        st, body = _signed(ctx, "POST", f"{base}/{index_b}/_search", _json_body(
            {"query": {"term": {"kind": "sim2real"}}, "size": 1}))
        total = body.get("hits", {}).get("total", {}) if st == 200 else None
        assert st == 200 and total == {"value": N_DOCS, "relation": "eq"}, (
            f"search {i} returned HTTP {st} total {total!r}, expected {N_DOCS} eq"
        )

    t_search_end = _now()

    doc_names = ["SearchableDocuments", "Nodes"] + status_names
    want_docs = baseline + N_DOCS

    def _docs_state(series, ts):
        vals = [series[n].get(ts) for n in doc_names]
        return vals == [want_docs, 1.0, 1.0, 0.0, 0.0]

    _poll_metrics(ctx, cw, account_id, domain_name, doc_names, _next_minute(t_docs), _docs_state,
                  f"_bulk {N_DOCS} docs -> SearchableDocuments=={baseline:g}+{N_DOCS}, "
                  f"Nodes==1, ClusterStatus green")

    # SearchRate is a per-minute count that is NOT zero at rest (the service's own traffic read 0-3
    # per minute on an idle domain), so "> 0" would pass on noise. The M searches must all be
    # accounted for: the per-minute counts summed over a window bounded on BOTH sides — from the
    # minute the searches began to two minutes past the minute they ended (the count is stamped up
    # to a minute after the work) — reach at least M.
    lo = _this_minute(t_search)
    hi = _this_minute(t_search_end) + datetime.timedelta(minutes=2)
    rate_start = time.monotonic()
    rate_cap_s = _cap_s(ctx, POLL_DEADLINE_S)
    while True:
        rate = _series(cw, account_id, domain_name, ["SearchRate"],
                       lo - datetime.timedelta(minutes=1), stat="Sum")["SearchRate"]
        window = {ts: v for ts, v in rate.items() if lo <= ts <= hi}
        if sum(window.values()) >= M_SEARCHES or time.monotonic() - rate_start >= rate_cap_s:
            break
        time.sleep(POLL_STEP_S)
    if sum(window.values()) < M_SEARCHES and rate_cap_s < POLL_DEADLINE_S:
        raise _not_graded(rate_start, POLL_DEADLINE_S, "SearchRate to count the searches")
    assert sum(window.values()) >= M_SEARCHES, (
        f"{M_SEARCHES} searches between {t_search.isoformat()} and {t_search_end.isoformat()} "
        f"surfaced as SearchRate {({ts.isoformat(): v for ts, v in sorted(window.items())})!r} "
        f"(sum {sum(window.values()):g}) in [{lo.isoformat()}, {hi.isoformat()}] within "
        f"{POLL_DEADLINE_S}s; expected a sum of at least {M_SEARCHES}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
