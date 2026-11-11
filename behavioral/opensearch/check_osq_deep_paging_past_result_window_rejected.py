"""osq-deep-paging-past-result-window-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "osq-deep-paging-past-result-window-rejected"
GROUP = "data-plane"
SERVICES = ["opensearch"]


# A dozen documents is plenty: the boundary being probed is `index.max_result_window` (10000 by
# default), which is a property of the index, not of how much data is in it.
PAGED_DOCS = [(f"r{n:02d}", {"label": f"item-{n:02d}", "rank": n}) for n in range(1, 13)]
MAX_RESULT_WINDOW = 10000


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:native", "plane:data")
def run(ctx) -> None:
    """A deep-paging search past `index.max_result_window` is REJECTED with
    search_phase_execution_exception / illegal_argument_exception and no documents, while the same
    query inside the window returns the exact page before and after -- a boundary, not a broken index."""
    domain_name = _create_min_domain(ctx)
    base = ctx.endpoint_url(_wait_domain_searchable(ctx, domain_name))
    _wait_data_plane_authorized(ctx, base)

    index = ctx.unique_name("sim2real-osq-window-")
    _create_index(ctx, base, index, {"label": {"type": "keyword"},
                                     "rank": {"type": "integer"}})
    _bulk_index(ctx, base, index, PAGED_DOCS)

    # The window is read from the index, never assumed: an account or a future default could set
    # it elsewhere, and then the "too large" offset below would be a different number.
    status, settings = _os_request(ctx, base, "GET", f"/{index}/_settings")
    assert status == 200, f"reading index settings returned {status}: {settings!r}"
    window = int(settings[index]["settings"]["index"].get("max_result_window", MAX_RESULT_WINDOW))
    assert window == MAX_RESULT_WINDOW, (
        f"expected the default result window of {MAX_RESULT_WINDOW}, index reports {window!r}")

    sort = [{"rank": {"order": "asc"}}]

    # POSITIVE CONTROL, before: a page well inside the window returns the exact documents.
    body = _search(ctx, base, index, {"size": 5, "from": 0, "sort": sort, "_source": ["rank"]})
    assert _total(body) == (12, "eq"), f"control page total was {_total(body)!r}"
    assert [hit["_source"]["rank"] for hit in body["hits"]["hits"]] == [1, 2, 3, 4, 5], (
        f"control page must be ranks 1..5, got {body['hits']['hits']!r}")

    # POSITIVE CONTROL, at the boundary: from + size == the window exactly is still LEGAL. It
    # returns no documents (there are only 12), which is a different fact from being rejected --
    # that is precisely the distinction an emulator with an off-by-one guard loses.
    status, body = _os_request(ctx, base, "POST", f"/{index}/_search",
                               {"size": 10, "from": window - 10, "sort": sort})
    assert status == 200, f"from+size == the window must be accepted, got {status}: {body!r}"
    assert body["hits"]["hits"] == [], (
        f"there is no 10000th document, so the boundary page must be empty, got "
        f"{body['hits']['hits']!r}")
    assert _total(body) == (12, "eq"), f"boundary page total was {_total(body)!r}"

    # THE ONE BROKEN THING: one document past the window.
    status, body = _os_request(ctx, base, "POST", f"/{index}/_search",
                               {"size": 10, "from": window - 9, "sort": sort})
    assert status == 400, (
        f"from+size one past the result window must be rejected with HTTP 400, got {status}: "
        f"{body!r}")
    assert body["status"] == 400, f"error body must carry status 400, got {body!r}"
    assert body["error"]["type"] == "search_phase_execution_exception", (
        f"expected search_phase_execution_exception, got {body['error'].get('type')!r}: {body!r}")
    root = body["error"]["root_cause"]
    assert [cause["type"] for cause in root] == ["illegal_argument_exception"], (
        f"expected a single illegal_argument_exception root cause, got {root!r}")
    assert str(window) in root[0]["reason"] and "Result window is too large" in root[0]["reason"], (
        f"the root cause must name the window it enforced, got {root[0]['reason']!r}")
    # EFFECT ABSENT: the rejection returned no documents and no partial page.
    assert "hits" not in body, f"a rejected search must return no hits section, got {body!r}"

    # POSITIVE CONTROL, after: the rejection did not break the index or the query path.
    body = _search(ctx, base, index, {"size": 5, "from": 5, "sort": sort, "_source": ["rank"]})
    assert _total(body) == (12, "eq"), f"post-rejection total was {_total(body)!r}"
    assert [hit["_source"]["rank"] for hit in body["hits"]["hits"]] == [6, 7, 8, 9, 10], (
        f"the next page must still be ranks 6..10 after the rejection, got "
        f"{body['hits']['hits']!r}")


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

# A data-plane FAIL marker: a detail carrying this string is scored as a real fidelity gap --
# "the domain published an endpoint that never answered" -- rather than as an environment error.
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
                # Tagged at creation so a tag-scanning sweep can still find the domain if
                # teardown is ever interrupted; the name prefix alone is not enough for every
                # sweep path.
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
