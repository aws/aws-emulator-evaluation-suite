"""osq-terms-aggregation-and-sorted-pagination."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "osq-terms-aggregation-and-sorted-pagination"
GROUP = "data-plane"
SERVICES = ["opensearch"]


# 12 documents with deliberately distinct per-category counts (5 / 4 / 2 / 1) and prices chosen
# so every aggregate below is an exact value rather than a float to be rounded.
CATALOG_DOCS = [
    ("a1", {"category": "alpha", "price": 10, "rank": 1}),
    ("a2", {"category": "alpha", "price": 20, "rank": 2}),
    ("a3", {"category": "alpha", "price": 30, "rank": 3}),
    ("a4", {"category": "alpha", "price": 40, "rank": 4}),
    ("a5", {"category": "alpha", "price": 50, "rank": 5}),
    ("b1", {"category": "beta", "price": 5, "rank": 6}),
    ("b2", {"category": "beta", "price": 10, "rank": 7}),
    ("b3", {"category": "beta", "price": 15, "rank": 8}),
    ("b4", {"category": "beta", "price": 20, "rank": 9}),
    ("g1", {"category": "gamma", "price": 100, "rank": 10}),
    ("g2", {"category": "gamma", "price": 200, "rank": 11}),
    ("d1", {"category": "delta", "price": 7, "rank": 12}),
]
EXPECTED_BUCKETS = [("alpha", 5, 30.0, 150.0), ("beta", 4, 12.5, 50.0),
                    ("gamma", 2, 150.0, 300.0), ("delta", 1, 7.0, 7.0)]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """A terms aggregation returns every bucket with the exact doc_count and sub-metric values
    the indexed documents imply, `size` truncation moves the remainder into sum_other_doc_count,
    and a sorted `from`/`size` walk returns each document exactly once with its painless script_field.
    """
    domain_name = _create_min_domain(ctx)
    base = ctx.endpoint_url(_wait_domain_searchable(ctx, domain_name))
    _wait_data_plane_authorized(ctx, base)

    index = ctx.unique_name("sim2real-osq-agg-")
    _create_index(ctx, base, index, {
        "category": {"type": "keyword"},
        "price": {"type": "integer"},
        "rank": {"type": "integer"},
    })
    _bulk_index(ctx, base, index, CATALOG_DOCS)

    # 1. Every bucket, in descending doc_count order, with its exact avg and sum sub-metrics.
    body = _search(ctx, base, index, {
        "size": 0,
        "aggs": {"by_category": {
            "terms": {"field": "category", "size": 10},
            "aggs": {"avg_price": {"avg": {"field": "price"}},
                     "sum_price": {"sum": {"field": "price"}}}}},
    })
    assert _total(body) == (12, "eq"), f"aggregation request total was {_total(body)!r}"
    assert body["hits"]["hits"] == [], (
        f"size:0 must return aggregations and no hits, got {body['hits']['hits']!r}")
    agg = body["aggregations"]["by_category"]
    observed = [(b["key"], b["doc_count"], b["avg_price"]["value"], b["sum_price"]["value"])
                for b in agg["buckets"]]
    assert observed == EXPECTED_BUCKETS, (
        f"terms buckets must be ordered by descending doc_count with exact sub-metrics, "
        f"expected {EXPECTED_BUCKETS!r}, got {observed!r}")
    assert agg["sum_other_doc_count"] == 0, (
        f"no bucket was truncated, so sum_other_doc_count must be 0, got "
        f"{agg['sum_other_doc_count']!r}")
    assert agg["doc_count_error_upper_bound"] == 0, (
        f"one shard means exact counts, so the error bound must be 0, got "
        f"{agg['doc_count_error_upper_bound']!r}")
    assert sum(b["doc_count"] for b in agg["buckets"]) == 12, (
        f"bucket counts must account for all 12 documents, got {observed!r}")

    # 2. Truncating to the top 2 buckets moves EXACTLY the remaining 3 documents into
    #    sum_other_doc_count -- the accounting an emulator that just groups a list gets wrong.
    body = _search(ctx, base, index, {
        "size": 0, "aggs": {"by_category": {"terms": {"field": "category", "size": 2}}}})
    agg = body["aggregations"]["by_category"]
    assert [(b["key"], b["doc_count"]) for b in agg["buckets"]] == [("alpha", 5), ("beta", 4)], (
        f"size:2 must keep the two largest buckets, got {agg['buckets']!r}")
    assert agg["sum_other_doc_count"] == 3, (
        f"gamma(2) + delta(1) must land in sum_other_doc_count, got "
        f"{agg['sum_other_doc_count']!r}")

    # 3. A filtered aggregation sees only the filtered documents: the same field, a different
    #    population, so the counts have to move with the query.
    body = _search(ctx, base, index, {
        "size": 0,
        "query": {"range": {"price": {"gte": 20}}},
        "aggs": {"by_category": {"terms": {"field": "category", "size": 10}}}})
    assert _total(body) == (7, "eq"), f"range query total was {_total(body)!r}"
    assert [(b["key"], b["doc_count"]) for b in body["aggregations"]["by_category"]["buckets"]] \
        == [("alpha", 4), ("gamma", 2), ("beta", 1)], (
        f"price>=20 leaves alpha(20,30,40,50), gamma(100,200) and beta(20), got "
        f"{body['aggregations']['by_category']['buckets']!r}")

    # 4. A sorted from/size walk returns every document exactly once, in rank order, with the
    #    painless script_field computed for each hit and the sort key echoed back.
    pages, seen = [], []
    for offset in (0, 5, 10, 12):
        body = _search(ctx, base, index, {
            "size": 5, "from": offset,
            "sort": [{"rank": {"order": "asc"}}],
            "_source": ["category", "rank"],
            "script_fields": {"rank_doubled": {
                "script": {"lang": "painless", "source": "doc['rank'].value * 2"}}},
        })
        assert _total(body) == (12, "eq"), (
            f"every page must report the same exact total, page at from={offset} said "
            f"{_total(body)!r}")
        page = []
        for hit in body["hits"]["hits"]:
            rank = hit["_source"]["rank"]
            assert hit["sort"] == [rank], (
                f"hit {hit['_id']!r} must echo its sort key, got {hit.get('sort')!r}")
            assert hit["fields"]["rank_doubled"] == [rank * 2], (
                f"painless script_field for {hit['_id']!r} must be [{rank * 2}], got "
                f"{hit['fields'].get('rank_doubled')!r}")
            page.append(rank)
        pages.append(page)
        seen.extend(_hit_ids(body))
    assert pages == [[1, 2, 3, 4, 5], [6, 7, 8, 9, 10], [11, 12], []], (
        f"a size:5 walk over 12 documents must page 5/5/2/0 in rank order, got {pages!r}")
    assert seen == [doc_id for doc_id, _ in sorted(CATALOG_DOCS, key=lambda d: d[1]["rank"])], (
        f"the walk must return every document exactly once in rank order, got {seen!r}")

    # 5. Reversing the sort reverses the first page: ordering is computed, not the insertion order.
    body = _search(ctx, base, index, {
        "size": 5, "sort": [{"rank": {"order": "desc"}}], "_source": ["rank"]})
    assert [hit["_source"]["rank"] for hit in body["hits"]["hits"]] == [12, 11, 10, 9, 8], (
        f"descending page 1 must be ranks 12..8, got {body['hits']['hits']!r}")


# ===== helpers =====

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# Smallest legal single-node topology: a domain bills per node-hour, so every check here
# provisions one t3.small.search data node, no dedicated cluster manager node, no zone awareness and the
# minimum gp3 volume, and registers teardown BEFORE the create call.
MIN_CLUSTER_CONFIG = {"InstanceType": "t3.small.search", "InstanceCount": 1}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}

# Pinned to the version these assertions were blessed against on real AWS. The query semantics
# asserted below (analyzer behaviour, terms-aggregation bucket accounting, sort + from/size
# paging, painless script_fields, the result-window guard) are stable across OpenSearch majors,
# but the engine version is part of what an emulator has to serve, so it is stated rather than
# inherited from whatever AWS currently defaults to.
ENGINE_VERSION = "OpenSearch_3.7"

# One shard, no replica: bucket counts, doc_count_error_upper_bound and relevance ordering are
# then properties of the data rather than of how the coordinator merged shard results.
INDEX_SETTINGS = {"number_of_shards": 1, "number_of_replicas": 0}

# A data-plane FAIL marker: a check detail containing this string means the domain's
# data-plane endpoint never answered a signed request, which is a real fidelity gap rather
# than an environment error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _os_request(ctx, base, method, path, body=None, *, ndjson=False, timeout=60):
    """One SigV4-signed ("es") request to the domain's OpenSearch REST data plane.

    The OpenSearch REST protocol is spoken by hand here: the request line and headers are framed
    onto a raw socket (TLS-wrapped when the endpoint is https) and the reply is parsed with
    ``http.client.HTTPResponse``. No third-party client is needed, and nothing about the exchange
    is delegated to a signed AWS API call -- which is the point, since this is the plane an
    emulator has to serve rather than describe.

    Returns ``(status, parsed_json)``. A non-2xx status is DATA the caller asserts on; a
    transport failure is not, so it becomes an AssertionError carrying the marker above.
    """
    import http.client
    import json as _json
    import socket
    import ssl
    from urllib.parse import urlparse

    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    # Sign with the credentials ctx wired for THIS account, never boto3's ambient chain:
    # the domain policy below is account-scoped, so signing as the ambient principal 403s.
    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()

    # Parse the endpoint rather than assuming TLS on 443: real AWS publishes a bare
    # `search-*.<region>.es.amazonaws.com` host, while an emulator's endpoint is typically
    # plaintext on another port, and hard-coding https/443 would make it unconnectable -- scored
    # as a data-plane failure instead of producing the fidelity signal this check exists for.
    parsed = urlparse(base if "//" in base else f"//{base}")
    host = parsed.hostname
    assert host, f"domain endpoint {base!r} has no host"
    scheme = "http" if parsed.scheme == "http" else "https"
    default_port = 443 if scheme == "https" else 80
    port = parsed.port or default_port
    netloc = host if port == default_port else f"{host}:{port}"

    if ndjson:
        payload = "".join(_json.dumps(line) + "\n" for line in body).encode()
        content_type = "application/x-ndjson"
    else:
        payload = b"" if body is None else _json.dumps(body).encode()
        content_type = "application/json"

    aws_req = AWSRequest(method=method, url=f"{scheme}://{netloc}{path}", data=payload,
                         headers={"Host": netloc, "Content-Type": content_type})
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)
    headers = dict(aws_req.headers)
    # Added AFTER signing deliberately: neither header is in SignedHeaders, and SigV4 only
    # requires the headers it signed to arrive unchanged. `Connection: close` keeps one request
    # per socket, so the response body is delimited by EOF and needs no keep-alive framing.
    headers["Content-Length"] = str(len(payload))
    headers["Connection"] = "close"
    head = (f"{method} {path} HTTP/1.1\r\n"
            + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n")

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: no TCP connection to the domain endpoint {netloc}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    try:
        conn = ssl.create_default_context().wrap_socket(sock, server_hostname=host) \
            if scheme == "https" else sock
        conn.sendall(head.encode() + payload)
        resp = http.client.HTTPResponse(conn, method=method)
        resp.begin()
        raw = resp.read()
        status = resp.status
    except (OSError, http.client.HTTPException) as exc:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} {path} on the domain endpoint did not "
            f"complete: {type(exc).__name__}: {exc}"
        ) from exc
    finally:
        sock.close()
    try:
        return status, (_json.loads(raw) if raw else {})
    except ValueError:
        return status, {"unparsed_body": raw.decode(errors="replace")}


def _searchable_domain_access_policy(ctx, domain_name: str) -> str:
    """A domain access policy allowing the caller's OWN account to use the data plane.

    The account comes from STS, never from a literal: the same check has to pass in any
    account, and an account id baked into a policy is exactly the overfitting that reads as a
    pass forever.
    """
    import json as _json

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return _json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}/*",
        }],
    })


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: a domain that was never created is already torn down."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_min_domain(ctx) -> str:
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-osq-")[:28].rstrip("-")
    # Registered BEFORE the create so a failure between the call and the registration can never
    # leak a cluster that bills 24x7.
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    for attempt in range(8):
        try:
            osc.create_domain(
                DomainName=domain_name,
                EngineVersion=ENGINE_VERSION,
                ClusterConfig=dict(MIN_CLUSTER_CONFIG),
                EBSOptions=dict(MIN_EBS_OPTIONS),
                AccessPolicies=_searchable_domain_access_policy(ctx, domain_name),
                # Tagged at creation so a tag search can still find the domain if teardown is
                # ever interrupted; the name prefix alone is not enough for every sweep path.
                TagList=[{"Key": "sim2real", "Value": CHECK}],
            )
            return domain_name
        except ClientError as exc:
            # CreateDomain is rate limited per account; a bounded back-off on throttling only.
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt))
    raise AssertionError(f"CreateDomain for {domain_name} was still throttled after 8 attempts")


def _domain_status(osc, domain_name: str, deadline: float) -> dict:
    """DescribeDomain's DomainStatus, retried every 2 s on throttling until ``deadline``."""
    while True:
        try:
            return osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            if (exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES
                    or time.monotonic() >= deadline):
                raise
        time.sleep(2.0)


def _wait_domain_searchable(ctx, domain_name: str, timeout_s: float = 1500.0) -> str:
    """Poll to Processing=False AND a published Endpoint -- never a bare sleep."""
    osc = ctx.client("opensearch")
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        last = _domain_status(osc, domain_name, deadline)
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2.0)
    detail = (f"domain {domain_name} never became searchable within {budget}s "
              f"(Processing={last.get('Processing')!r}, Endpoint={last.get('Endpoint')!r})")
    raise AssertionError(detail)


def _wait_data_plane_authorized(ctx, base: str, timeout_s: float = 420.0) -> dict:
    """A searchable domain is not yet an authorizing one: the access policy takes effect after
    the endpoint is published, so a signed GET / can 403 for a while. Poll the condition.
    """
    deadline = time.monotonic() + timeout_s
    status, body = None, None
    while time.monotonic() < deadline:
        status, body = _os_request(ctx, base, "GET", "/")
        if status != 403:
            break
        time.sleep(2.0)
    assert status == 200, f"signed GET / on the domain endpoint returned {status}: {body!r}"
    return body


def _create_index(ctx, base: str, index: str, properties: dict) -> None:
    status, body = _os_request(ctx, base, "PUT", f"/{index}", {
        "settings": {"index": dict(INDEX_SETTINGS)},
        "mappings": {"dynamic": "strict", "properties": properties},
    })
    assert status == 200, f"creating index {index} returned {status}: {body!r}"
    assert body.get("acknowledged") is True, f"index create not acknowledged: {body!r}"
    # Deleting the index is not what stops the bill -- the domain teardown does -- but it keeps
    # a retried or re-run check from ever reading stale documents.
    ctx.on_cleanup(lambda: _os_request(ctx, base, "DELETE", f"/{index}"))


def _bulk_index(ctx, base: str, index: str, docs: list) -> None:
    """Index *docs* (a list of ``(id, source)``) with _bulk, then refresh, then assert the
    documents are all actually there -- an accepted write is not a stored document."""
    lines = []
    for doc_id, source in docs:
        lines.append({"index": {"_index": index, "_id": doc_id}})
        lines.append(source)
    status, body = _os_request(ctx, base, "POST", "/_bulk", lines, ndjson=True)
    assert status == 200, f"_bulk returned {status}: {body!r}"
    assert body.get("errors") is False, f"_bulk reported item errors: {body!r}"
    results = [(item["index"]["_id"], item["index"]["status"]) for item in body["items"]]
    assert results == [(doc_id, 201) for doc_id, _ in docs], (
        f"_bulk did not report one 201 Created per document in order: {results!r}")
    status, body = _os_request(ctx, base, "POST", f"/{index}/_refresh")
    assert status == 200, f"_refresh returned {status}: {body!r}"
    status, body = _os_request(ctx, base, "POST", f"/{index}/_count", {"query": {"match_all": {}}})
    assert status == 200, f"_count returned {status}: {body!r}"
    assert body.get("count") == len(docs), (
        f"expected {len(docs)} documents after refresh, _count says {body.get('count')!r}")


def _search(ctx, base: str, index: str, query: dict) -> dict:
    status, body = _os_request(ctx, base, "POST", f"/{index}/_search", query)
    assert status == 200, f"_search {query!r} returned {status}: {body!r}"
    return body


def _hit_ids(body: dict) -> list:
    return [hit["_id"] for hit in body["hits"]["hits"]]


def _total(body: dict) -> tuple:
    total = body["hits"]["total"]
    return total["value"], total["relation"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
