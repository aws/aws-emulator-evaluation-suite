"""search-aggregation-query-bucket-ordering."""
from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "search-aggregation-query-bucket-ordering"
GROUP = 'data-plane'
SERVICES = ['opensearch']

# ===== self-contained helpers =====

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology. Domains bill per node-hour and leaked domains were a
# real cost-leak class, so every check here provisions the cheapest legal cluster (one
# t3.small.search data node, no dedicated cluster manager nodes, no zone awareness, minimum gp3 volume)
# and registers teardown BEFORE the create call.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


# Marks a resource state the target accepted and never converged, so it reads as the
# target's own fault rather than a slow environment.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state: a failure on every target.

    The message carries the sentinel so the failure is attributed to the target.
    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created / already deleted."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _account_access_policy(ctx, domain_name: str) -> str:
    """Resource-based policy letting this account's principals use the data plane."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}/*",
        }],
    })


def _create_min_domain(ctx, *, scenario: str, access_policies=None, **overrides) -> str:
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    # Registered BEFORE the create so a failure between create and registration can never
    # leak a 24x7 cluster.
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        AccessPolicies=(
            access_policies if access_policies is not None
            else _account_access_policy(ctx, domain_name)
        ),
        # Tagged at creation so a tag-based cleanup can find an orphaned domain.
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: jitter before the first attempt to
    # spread concurrent runs, then backoff on throttling. Both sleeps live inside the bounded
    # retry loop (a stated deadline of 12 attempts) rather than before it.
    for attempt in range(12):
        try:
            if attempt == 0:
                time.sleep(random.uniform(0, 20.0))
            else:
                time.sleep(6.0 * attempt + random.uniform(0, 6.0))
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1800.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep."""
    osc = ctx.client("opensearch")
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2)
    raise _never_ready(
        f"domain {domain_name} never became searchable within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx wired for the target account (not boto3's ambient chain):
    signing as the wrong principal makes the domain's account-scoped policy 403 the request.
    Sends with stdlib urllib so no third-party HTTP client is needed.
    """
    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()
    if raw is not None:
        data = raw if isinstance(raw, bytes) else raw.encode()
    elif body is not None:
        data = json.dumps(body).encode()
    else:
        data = None
    headers = {"Content-Type": content_type} if data is not None else {}
    aws_req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)
    req = urllib.request.Request(url, data=data, method=method, headers=dict(aws_req.headers))
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(text)
        except ValueError:
            return exc.code, {"raw": text}


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 300.0) -> None:
    """Processing=False + a published Endpoint does NOT mean the data-plane authorizer has
    the access policy yet; signed requests can 403 for a while. Poll a cheap GET until clear.
    """
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status, _ = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            return
        time.sleep(2)
    raise AssertionError(f"domain data plane still 403 after {timeout_s}s (last status {status})")


def _ndjson(lines) -> str:
    """_bulk wants newline-delimited JSON with a MANDATORY trailing newline."""
    return "".join(json.dumps(line) + "\n" for line in lines)


# ===== end self-contained helpers =====

# Fixed corpus so every bucket count and every stats value is exact and hand-checkable.
DOCS = [
    {"category": "red", "price": 10},
    {"category": "red", "price": 20},
    {"category": "red", "price": 30},
    {"category": "blue", "price": 5},
    {"category": "blue", "price": 15},
    {"category": "green", "price": 100},
]


def _buckets(result):
    return result.get("aggregations", {}).get("by_cat", {}).get("buckets", [])


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A terms aggregation with a nested stats sub-aggregation returns exact bucket counts and stats,
    buckets ordered doc_count-desc with ties broken by key-asc, and size:0 suppresses hits while
    still reporting the true total."""
    domain = _create_min_domain(ctx, scenario=CHECK)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = "sim2real-behav-aggs"
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {
            "category": {"type": "keyword"},
            "price": {"type": "integer"},
        }},
    })
    assert status in (200, 201), f"creating index failed with HTTP {status}: {created}"

    lines = []
    for i, doc in enumerate(DOCS):
        lines.append({"index": {"_index": index, "_id": f"d{i}"}})
        lines.append(doc)
    status, bulk = _signed_request(
        ctx, "POST", f"{base}/_bulk", raw=_ndjson(lines), content_type="application/x-ndjson"
    )
    assert status == 200, f"_bulk load failed with HTTP {status}: {bulk}"
    assert bulk.get("errors") is False, f"fixture load reported item errors: {bulk}"

    status, refreshed = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"_refresh failed with HTTP {status}: {refreshed}"

    agg_body = {
        "size": 0,
        "aggs": {"by_cat": {
            "terms": {"field": "category"},
            "aggs": {"price_stats": {"stats": {"field": "price"}}},
        }},
    }
    status, result = _signed_request(ctx, "POST", f"{base}/{index}/_search", body=agg_body)
    assert status == 200, f"aggregation _search failed with HTTP {status}: {result}"

    total = result.get("hits", {}).get("total", {})
    total_value = total.get("value") if isinstance(total, dict) else total
    assert total_value == 6, f"hits.total.value must be 6, got {total_value}"
    assert result["hits"]["hits"] == [], (
        f"size:0 must suppress the hit list, got {result['hits']['hits']}"
    )

    buckets = _buckets(result)
    assert [b["key"] for b in buckets] == ["red", "blue", "green"], (
        f"terms buckets must be ordered by doc_count desc, got {[b['key'] for b in buckets]}"
    )
    assert [b["doc_count"] for b in buckets] == [3, 2, 1], (
        f"terms bucket doc_counts wrong: {[b['doc_count'] for b in buckets]}"
    )

    expected_stats = {
        "red": {"count": 3, "min": 10.0, "max": 30.0, "sum": 60.0, "avg": 20.0},
        "blue": {"count": 2, "min": 5.0, "max": 15.0, "sum": 20.0, "avg": 10.0},
        "green": {"count": 1, "min": 100.0, "max": 100.0, "sum": 100.0, "avg": 100.0},
    }
    for bucket in buckets:
        stats = bucket.get("price_stats", {})
        want = expected_stats[bucket["key"]]
        for field, value in want.items():
            assert float(stats.get(field)) == float(value), (
                f"stats sub-aggregation for {bucket['key']}: {field} should be {value}, "
                f"got {stats.get(field)} (full bucket {bucket})"
            )

    # Explicit _key ordering must be honoured, not ignored in favour of doc_count.
    key_order_body = {
        "size": 0,
        "aggs": {"by_cat": {"terms": {"field": "category", "order": {"_key": "asc"}}}},
    }
    status, by_key = _signed_request(ctx, "POST", f"{base}/{index}/_search", body=key_order_body)
    assert status == 200, f"_key-ordered aggregation failed with HTTP {status}: {by_key}"
    assert [b["key"] for b in _buckets(by_key)] == ["blue", "green", "red"], (
        f'order:{{"_key":"asc"}} ignored, got {[b["key"] for b in _buckets(by_key)]}'
    )

    # Query-scoped aggregation: only prices >= 15 count, and the blue/green doc_count tie
    # must be broken by key ascending.
    filtered_body = {
        "size": 0,
        "query": {"range": {"price": {"gte": 15}}},
        "aggs": {"by_cat": {"terms": {"field": "category"}}},
    }
    status, filtered = _signed_request(ctx, "POST", f"{base}/{index}/_search", body=filtered_body)
    assert status == 200, f"filtered aggregation failed with HTTP {status}: {filtered}"
    filtered_buckets = _buckets(filtered)
    assert [b["key"] for b in filtered_buckets] == ["red", "blue", "green"], (
        "a doc_count tie must be broken by key ascending, got "
        f"{[b['key'] for b in filtered_buckets]}"
    )
    assert [b["doc_count"] for b in filtered_buckets] == [2, 1, 1], (
        f"aggregation did not respect the query filter: {filtered_buckets}"
    )

    status, deleted = _signed_request(ctx, "DELETE", f"{base}/{index}")
    assert status == 200, f"index delete failed with HTTP {status}: {deleted}"
    status, gone = _signed_request(ctx, "GET", f"{base}/{index}")
    assert status == 404, f"deleted index {index} is still reachable, got HTTP {status}: {gone}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
