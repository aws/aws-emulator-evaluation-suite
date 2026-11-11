"""sorting-and-aggregating-a-text-field-rejected-while-its-keyword-subfield-serves-both."""
from __future__ import annotations

import http.client
import json
import random
import socket
import ssl
import time
from urllib.parse import urlsplit

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "sorting-and-aggregating-a-text-field-rejected-while-its-keyword-subfield-serves-both"
GROUP = 'data-plane'
SERVICES = ['opensearch']

# ===== self-contained helpers =====

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology: one t3.small.search data node, no dedicated cluster manager
# nodes, no zone awareness, minimum gp3 volume; teardown is registered before create.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# Marks a failure of the domain endpoint the target itself published, so it reads as the
# target's own fault rather than a connection problem on the caller's side.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
# The CONTROL-PLANE convergence counterpart, for a domain that was accepted and never converged.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state: a failure on every target.

    The message carries the sentinel so the failure is attributed to the target.
    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created / already deleted.

    Deliberately NOT silent about anything else. ``ctx.on_cleanup`` swallows exceptions, so a
    delete that fails for any other reason leaks a 24x7 cluster while the check still passes --
    raising here is what puts the failure in the run log where an operator can see it.
    """
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


def _create_min_domain(ctx, *, scenario: str, **overrides) -> str:
    """Create the cheapest legal domain, cleanup registered BEFORE the create call."""
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    # Registered BEFORE the create so a failure between create and registration can never leak a
    # 24x7 cluster.
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        AccessPolicies=_account_access_policy(ctx, domain_name),
        # Tagged at creation so a tag-based cleanup can find an orphaned domain.
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: jitter on the first attempt, then
    # back off on throttling -- both live inside this bounded (12-attempt), raise-on-exhaustion
    # loop so neither sleep is unconditional.
    for attempt in range(12):
        time.sleep(random.uniform(0, 20.0) if attempt == 0 else 6.0 * attempt + random.uniform(0, 6.0))
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1200.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep.

    The budget keeps the whole check under 30 minutes.
    """
    osc = ctx.client("opensearch")
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        try:
            last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            # Concurrent domain polls in one account hit DescribeDomain's rate limit: poll again.
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(2)
            continue
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2)
    raise _never_ready(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, timeout=60):
    """SigV4-signed ('es') OpenSearch REST request over a socket THIS CHECK owns -> (status, json).

    Three properties, each load-bearing:

    * Signed with the credentials ctx wired for the target account, read off the opensearch
      client's own signer rather than boto3's ambient chain -- the domain policy is scoped to the
      target account root, so signing as any other ambient principal 403s in a way that reads
      exactly like a fidelity failure.
    * The TCP connection and the TLS handshake are made here (``socket.create_connection`` +
      ``SSLContext.wrap_socket``) and the HTTP/1.1 request line, headers and body are framed here,
      so the check speaks OpenSearch's own wire protocol end to end instead of delegating the
      transport to a URL opener. ``http.client.HTTPResponse`` is used only to PARSE the response
      off the socket we already hold, which is why no third-party HTTP or OpenSearch client is
      needed (and why none may be added: none is installed on the runner).
    * ``Connection: close`` because every request here is independent; keep-alive would buy
      nothing and leave a socket to reap.
    """
    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    aws_req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)

    parts = urlsplit(url)
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    lines = [f"{method} {target} HTTP/1.1", f"Host: {parts.netloc}", "Connection: close",
             "Accept: application/json"]
    lines += [f"{k}: {v}" for k, v in aws_req.headers.items()
              if k.lower() not in ("host", "connection", "accept")]
    if data is not None:
        lines.append(f"Content-Length: {len(data)}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + (data or b"")

    try:
        secure = parts.scheme == "https"
        sock = socket.create_connection((parts.hostname, parts.port or (443 if secure else 80)), timeout=timeout)
        try:
            tls = ssl.create_default_context().wrap_socket(sock, server_hostname=parts.hostname) if secure else sock
        except BaseException:
            sock.close()
            raise
        try:
            tls.sendall(raw)
            resp = http.client.HTTPResponse(tls, method=method)
            resp.begin()
            status, text = resp.status, resp.read().decode(errors="replace")
        finally:
            tls.close()
    except (OSError, http.client.HTTPException) as exc:  # the endpoint did not answer at all
        # An HTTP status is data the caller asserts on; a transport failure is not. The endpoint
        # here was published by the target itself, so failing to answer on it is the target's
        # failure.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} {target} to the domain endpoint did not "
            f"complete: {type(exc).__name__}: {exc}"
        ) from exc
    try:
        return status, (json.loads(text) if text else {})
    except ValueError:
        return status, {"raw": text}


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 300.0) -> None:
    """Processing=False + a published Endpoint does NOT mean the data-plane authorizer has the
    access policy yet; signed requests can 403 for a while. Poll a cheap GET until it clears.
    """
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status, _ = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            return
        time.sleep(2)
    raise _never_ready(
        f"domain data plane still answered 403 after {timeout_s}s (last status {status})",
    )


def _error_type(payload) -> str:
    """OpenSearch engine errors carry {'error': {'type': ..., 'reason': ...}, 'status': n}."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type") or "")
    return ""


def _root_cause_type(payload) -> str:
    """The FIRST root cause's type, which is where a shard-level refusal names itself.

    A search refusal is reported twice: the coordinating node wraps every shard failure in one
    `search_phase_execution_exception`, and the shard's own verdict is the root cause. Asserting
    only the wrapper would pass any emulator that fails a search for ANY reason, so both halves are
    asserted separately -- never as an alternation.
    """
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        causes = error.get("root_cause")
        if isinstance(causes, list) and causes and isinstance(causes[0], dict):
            return str(causes[0].get("type") or "")
    return ""


def _hit_titles(payload) -> list:
    """The `title` of every hit, in the order the engine returned them."""
    return [h.get("_source", {}).get("title") for h in payload.get("hits", {}).get("hits", [])]


# ===== end self-contained helpers =====

# Titles whose lexicographic order differs from their insertion order, so a sort that is silently
# ignored is not mistaken for a sort that worked.
TITLES = {"d1": "gamma release", "d2": "alpha release", "d3": "beta release"}
SORTED_TITLES = ["alpha release", "beta release", "gamma release"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:native", "plane:data")
def run(ctx) -> None:
    """OpenSearch refuses to sort or aggregate on an analysed `text` field (HTTP 400,
    search_phase_execution_exception wrapping illegal_argument_exception) while the same field
    matches and its `keyword` sub-field serves both, re-proved after the refusals."""
    domain = _create_min_domain(ctx, scenario=CHECK)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = ctx.unique_name("sim2real-fdata-")
    # One shard, no replicas: with a single shard the terms aggregation's counts are exact, and a
    # shard-level refusal cannot be masked by a partially successful search across shards.
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {
            "title": {"type": "text", "fields": {"raw": {"type": "keyword"}}}}},
    })
    assert status == 200, f"creating the index failed with HTTP {status}: {created}"
    assert created.get("acknowledged") is True, f"index creation not acknowledged: {created!r}"

    for doc_id, title in TITLES.items():
        status, indexed = _signed_request(ctx, "PUT", f"{base}/{index}/_doc/{doc_id}",
                                          body={"title": title})
        assert status == 201, f"indexing {doc_id} returned HTTP {status}: {indexed}"
        assert indexed.get("result") == "created", (
            f"indexing {doc_id} reported result {indexed.get('result')!r}, expected 'created'"
        )
    status, refreshed = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"refreshing the index returned HTTP {status}: {refreshed}"

    # Control 1: the text field IS searchable -- the refusals below are about field data, not about
    # the field being absent or unindexed.
    status, matched = _signed_request(ctx, "POST", f"{base}/{index}/_search",
                                      body={"query": {"match": {"title": "release"}}})
    assert status == 200, f"matching the text field returned HTTP {status}: {matched}"
    assert sorted(_hit_titles(matched)) == SORTED_TITLES, (
        f"a `match` on the analysed text field must find all three documents; got "
        f"{_hit_titles(matched)!r}"
    )

    # Control 2: its keyword sub-field sorts.
    status, by_keyword = _signed_request(ctx, "POST", f"{base}/{index}/_search",
                                         body={"sort": [{"title.raw": "asc"}]})
    assert status == 200, f"sorting on title.raw returned HTTP {status}: {by_keyword}"
    assert _hit_titles(by_keyword) == SORTED_TITLES, (
        f"sorting on the keyword sub-field must order the documents lexicographically; got "
        f"{_hit_titles(by_keyword)!r}"
    )

    # Control 3: and it aggregates.
    status, agg_keyword = _signed_request(
        ctx, "POST", f"{base}/{index}/_search",
        body={"size": 0, "aggs": {"titles": {"terms": {"field": "title.raw"}}}})
    assert status == 200, f"aggregating on title.raw returned HTTP {status}: {agg_keyword}"
    keyword_buckets = {b["key"]: b["doc_count"] for b in
                       agg_keyword.get("aggregations", {}).get("titles", {}).get("buckets", [])}
    assert keyword_buckets == {t: 1 for t in SORTED_TITLES}, (
        f"terms over the keyword sub-field must yield one bucket per title; got "
        f"{keyword_buckets!r}"
    )

    # Negative 1: the identical sort against the analysed field is refused.
    status, sort_refused = _signed_request(ctx, "POST", f"{base}/{index}/_search",
                                           body={"sort": [{"title": "asc"}]})
    assert status == 400, (
        f"sorting on an analysed text field must be refused with HTTP 400, got {status}: "
        f"{sort_refused}"
    )
    assert _error_type(sort_refused) == "search_phase_execution_exception", (
        f"expected search_phase_execution_exception, got {_error_type(sort_refused)!r}: "
        f"{sort_refused}"
    )
    assert _root_cause_type(sort_refused) == "illegal_argument_exception", (
        f"the shard-level cause must be illegal_argument_exception (field data disabled), got "
        f"{_root_cause_type(sort_refused)!r}: {sort_refused}"
    )
    # Effect absent: a refused search returns NO results, not an unsorted or partial page.
    assert "hits" not in sort_refused, (
        f"a refused search must return no hits section at all; got {sort_refused.get('hits')!r}"
    )

    # Negative 2: so is the identical aggregation.
    status, agg_refused = _signed_request(
        ctx, "POST", f"{base}/{index}/_search",
        body={"size": 0, "aggs": {"titles": {"terms": {"field": "title"}}}})
    assert status == 400, (
        f"aggregating on an analysed text field must be refused with HTTP 400, got {status}: "
        f"{agg_refused}"
    )
    assert _error_type(agg_refused) == "search_phase_execution_exception", (
        f"expected search_phase_execution_exception, got {_error_type(agg_refused)!r}: {agg_refused}"
    )
    assert _root_cause_type(agg_refused) == "illegal_argument_exception", (
        f"the shard-level cause must be illegal_argument_exception (field data disabled), got "
        f"{_root_cause_type(agg_refused)!r}: {agg_refused}"
    )
    assert "aggregations" not in agg_refused, (
        f"a refused aggregation must return no aggregations section; got "
        f"{agg_refused.get('aggregations')!r}"
    )

    # The refusals were query-time decisions: the documents and both accepted read paths are
    # untouched.
    status, still_sorted = _signed_request(ctx, "POST", f"{base}/{index}/_search",
                                           body={"sort": [{"title.raw": "asc"}]})
    assert status == 200, f"the control sort failed after the refusals with HTTP {status}"
    assert _hit_titles(still_sorted) == SORTED_TITLES, (
        f"the refused requests changed what the accepted sort returns: {_hit_titles(still_sorted)!r}"
    )
    status, count = _signed_request(ctx, "GET", f"{base}/{index}/_count")
    assert status == 200, f"counting the index after the refusals returned HTTP {status}: {count}"
    assert count.get("count") == len(TITLES), (
        f"the refused requests changed the document count to {count.get('count')!r}, expected "
        f"{len(TITLES)}"
    )

    _signed_request(ctx, "DELETE", f"{base}/{index}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
