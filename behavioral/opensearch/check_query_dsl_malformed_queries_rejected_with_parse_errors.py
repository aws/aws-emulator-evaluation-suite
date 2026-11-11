"""query-dsl-malformed-queries-rejected-with-parse-errors."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "query-dsl-malformed-queries-rejected-with-parse-errors"
GROUP = "data-plane"
SERVICES = ["opensearch"]

DOCS = [
    ("q1", {"name": "alpha", "rank": 3}),
    ("q2", {"name": "bravo", "rank": 2}),
    ("q3", {"name": "charlie", "rank": 1}),
]

# (label, search body, expected error). Each body breaks exactly one thing in an otherwise
# ordinary request. The positions inside a reason are those of the body as serialized by
# json.dumps with its default separators, which is how _os_request sends it.
MALFORMED = [
    ("unknown query type",
     {"query": {"no_such_query": {"name": "alpha"}}},
     {"type": "parsing_exception", "reason": "unknown query [no_such_query]",
      "caused_by": {"type": "named_object_not_found_exception",
                    "reason": "[1:29] unknown field [no_such_query]"}}),
    ("term query naming two fields",
     {"query": {"term": {"name": "alpha", "rank": 3}}},
     {"type": "parsing_exception",
      "reason": "[term] query doesn't support multiple fields, found [name] and [rank]"}),
    ("unknown bool clause",
     {"query": {"bool": {"must_sometimes": [{"match_all": {}}]}}},
     {"type": "x_content_parse_exception", "reason": "[1:21] [bool] unknown field [must_sometimes]"}),
    ("range operator gtx",
     {"query": {"range": {"rank": {"gtx": 1}}}},
     {"type": "parsing_exception", "reason": "[range] query does not support [gtx]"}),
    ("exists without a field",
     {"query": {"exists": {}}},
     {"type": "parsing_exception", "reason": "[exists] must be provided with a [field]"}),
    ("unknown top-level key",
     {"querry": {"match_all": {}}},
     {"type": "parsing_exception", "reason": "Unknown key for a START_OBJECT in [querry]."}),
    ("sort order outside asc/desc",
     {"sort": [{"rank": {"order": "sideways"}}]},
     {"type": "x_content_parse_exception", "reason": "[1:30] [field_sort] failed to parse field [order]",
      "caused_by": {"type": "illegal_argument_exception",
                    "reason": "No enum constant org.opensearch.search.sort.SortOrder.SIDEWAYS"}}),
    ("negative size",
     {"size": -5, "query": {"match_all": {}}},
     {"type": "illegal_argument_exception", "reason": "[size] parameter cannot be negative, found [-5]"}),
]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:native",
      "plane:data")
def run(ctx) -> None:
    """Malformed query DSL is refused with 400, no hits and the engine's exact error type, reason and cause,
    while a well-formed query on the same index returns the same exact result before and after.
    """
    domain_name = _create_min_domain(ctx)
    base = ctx.endpoint_url(_wait_domain_searchable(ctx, domain_name))
    _wait_data_plane_authorized(ctx, base)

    index = ctx.unique_name("sim2real-osdsl-")
    _create_index(ctx, base, index, {"name": {"type": "keyword"}, "rank": {"type": "integer"}})
    _bulk_index(ctx, base, index, DOCS)

    _assert_control(ctx, base, index, "before the malformed queries")

    for label, query, expected in MALFORMED:
        status, body = _os_request(ctx, base, "POST", f"/{index}/_search", query)
        assert status == 400, f"{label}: {query!r} must be refused with 400, got {status}: {body!r}"
        assert body.get("status") == 400, f"{label}: error body must carry status 400: {body!r}"
        assert "hits" not in body, f"{label}: a refused search returned hits: {body!r}"
        error = body.get("error", {})
        got = {k: error.get(k) for k in expected if k != "caused_by"}
        want = {k: v for k, v in expected.items() if k != "caused_by"}
        assert got == want, f"{label}: error {got!r}, expected {want!r}; body {body!r}"
        root = [(c.get("type"), c.get("reason")) for c in error.get("root_cause", [])]
        assert root == [(expected["type"], expected["reason"])], (
            f"{label}: root_cause {root!r}, expected the error itself")
        if "caused_by" in expected:
            cause = {k: error.get("caused_by", {}).get(k) for k in ("type", "reason")}
            assert cause == expected["caused_by"], (
                f"{label}: caused_by {cause!r}, expected {expected['caused_by']!r}")
        else:
            assert "caused_by" not in error, f"{label}: unexpected caused_by in {error!r}"

    _assert_control(ctx, base, index, "after the malformed queries")


def _assert_control(ctx, base: str, index: str, when: str) -> None:
    """POSITIVE CONTROL: a well-formed term + range query returns exactly the matching document."""
    body = _search(ctx, base, index, {"query": {"bool": {
        "filter": [{"term": {"name": "bravo"}}, {"range": {"rank": {"gte": 2}}}]}}})
    assert _total(body) == (1, "eq"), f"control {when}: total was {_total(body)!r}"
    assert _hit_ids(body) == ["q2"], f"control {when}: hits were {_hit_ids(body)!r}"


_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# Smallest legal single-node topology: a domain bills per node-hour, so every check here
# provisions one t3.small.search data node, no dedicated cluster manager, no zone awareness and the
# minimum gp3 volume, and registers teardown BEFORE the create call.
MIN_CLUSTER_CONFIG = {"InstanceType": "t3.small.search", "InstanceCount": 1}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}

# The engine version is part of what an emulator has to serve, so it is pinned rather than
# inherited from the AWS default.
ENGINE_VERSION = "OpenSearch_3.7"

# One shard, no replica: bucket counts, doc_count_error_upper_bound and relevance ordering are
# then properties of the data rather than of how the coordinator merged shard results.
INDEX_SETTINGS = {"number_of_shards": 1, "number_of_replicas": 0}

# A detail containing this marker is scored as a fidelity fail, not an environment error: a
# published endpoint that never answers is a data-plane gap.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _os_request(ctx, base, method, path, body=None, *, ndjson=False, timeout=60):
    """One SigV4-signed ("es") REST request over a raw socket; returns ``(status, parsed_json)``.
    A non-2xx status is data; a transport failure raises AssertionError carrying the marker."""
    import http.client
    import json as _json
    import socket
    import ssl
    from urllib.parse import urlparse

    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    # Sign with ctx's credentials, never boto3's ambient chain: the domain policy is account-scoped.
    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()

    # Parse the endpoint rather than assume https/443: an emulator may serve plaintext elsewhere.
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
    """A domain access policy allowing the caller's own account, read from STS, the data plane."""
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
                # Tagged at creation so a tag-based cleanup still finds an orphaned domain.
                TagList=[{"Key": "sim2real", "Value": CHECK}],
            )
            return domain_name
        except ClientError as exc:
            # CreateDomain is rate limited per account; a bounded back-off on throttling only.
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt))
    raise AssertionError(f"CreateDomain for {domain_name} was still throttled after 8 attempts")


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_domain_searchable(ctx, domain_name: str, timeout_s: float = 1500.0) -> str:
    """Poll to Processing=False AND a published Endpoint -- never a bare sleep."""
    osc = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        try:
            last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            # DescribeDomain throttles under the suite's concurrent polls: poll again to the deadline.
            if exc.response["Error"]["Code"] != "ThrottlingException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
            continue
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2.0)
    raise AssertionError(
        f"{DATAPLANE_MARKER}: domain {domain_name} never became searchable within {timeout_s}s "
        f"(Processing={last.get('Processing')!r}, Endpoint={last.get('Endpoint')!r})")


def _wait_data_plane_authorized(ctx, base: str, timeout_s: float = 420.0) -> dict:
    """A searchable domain is not yet an authorizing one: the access policy takes effect after
    the endpoint is published, so a signed GET / can 403 for a while. Poll the condition.
    """
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
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
    # The domain teardown stops the bill; deleting the index keeps a retry off stale documents.
    ctx.on_cleanup(lambda: _delete_index(ctx, base, index))


def _delete_index(ctx, base: str, index: str) -> None:
    """Delete one index; an index already gone (404) is the only tolerated outcome besides 200."""
    status, body = _os_request(ctx, base, "DELETE", f"/{index}")
    if status not in (200, 404):
        raise AssertionError(f"deleting index {index} returned {status}: {body!r}")


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
