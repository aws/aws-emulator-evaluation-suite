"""nested-mapping-isolates-sub-documents-from-flattened-object-matching."""
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

CHECK = "nested-mapping-isolates-sub-documents-from-flattened-object-matching"
GROUP = 'data-plane'
SERVICES = ['opensearch']


ENGINE_VERSION = "OpenSearch_2.11"
# Cheapest legal single-node topology: domains bill per node-hour.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# Marks a published domain endpoint that failed to answer as a data-plane failure.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _never_ready(msg: str) -> AssertionError:
    """The error for a resource that never converged; returned to keep ``from exc`` chaining."""
    return AssertionError(msg)


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Delete the domain, tolerating one that was never created or is already deleted."""
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
    # Registered before the create so a failure in between cannot leak a running cluster.
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        AccessPolicies=_account_access_policy(ctx, domain_name),
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: jitter, then back off on throttling.
    for attempt in range(12):
        time.sleep(random.uniform(0, 20.0) if attempt == 0 else 6.0 * attempt + random.uniform(0, 6.0))
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    raise AssertionError("CreateDomain still throttled after 12 attempts")


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


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1200.0) -> str:
    """Poll until Processing=False and an Endpoint is published.

    Provisioning this topology takes roughly 11-14 minutes.
    """
    osc = ctx.client("opensearch")
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        last = _domain_status(osc, domain_name, deadline)
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2.0)
    raise _never_ready(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, timeout=60):
    """SigV4-signed ('es') OpenSearch REST request over a raw socket -> (status, json).

    Signs with the opensearch client's own credentials: the domain policy is scoped to that account.
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
        # The endpoint was published by the target itself, so not answering on it is a failure.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} {target} to the domain endpoint did not "
            f"complete: {type(exc).__name__}: {exc}"
        ) from exc
    try:
        return status, (json.loads(text) if text else {})
    except ValueError:
        return status, {"raw": text}


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 300.0) -> None:
    """Poll a cheap GET until it stops returning 403.

    A published Endpoint does not mean the data-plane authorizer has the access policy yet.
    """
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status, _ = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            return
        time.sleep(2.0)
    raise _never_ready(
        f"domain data plane still answered 403 after {timeout_s}s (last status {status})",
    )


def _hit_ids(payload) -> list:
    """The _id of every hit, in the order the engine returned them."""
    return [h.get("_id") for h in payload.get("hits", {}).get("hits", [])]


def _total(payload) -> int:
    """`hits.total.value` -- the only place a match COUNT is reported."""
    return payload.get("hits", {}).get("total", {}).get("value")


# Two sub-objects on c1 whose (assignee, state) pairs do NOT coexist in either one, and one
# sub-object on c2 that IS the searched pair. That makes alice+closed match c2 under both mappings
# and c1 under the flattened one only, so the isolation claim has a positive inside it.
DOCS = {
    "c1": {"case": "c1", "tickets": [{"assignee": "alice", "state": "open"},
                                     {"assignee": "bob", "state": "closed"}]},
    "c2": {"case": "c2", "tickets": [{"assignee": "alice", "state": "closed"}]},
}
CROSS_QUERY = {"bool": {"must": [{"term": {"tickets.assignee": "alice"}},
                                 {"term": {"tickets.state": "closed"}}]}}
NESTED_AGG = {"size": 0, "aggs": {"tickets": {
    "nested": {"path": "tickets"},
    "aggs": {"by_assignee": {"terms": {"field": "tickets.assignee"}}}}}}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:native", "plane:data")
def run(ctx) -> None:
    """A `nested` mapping keeps each array sub-object a separate document, so a conjunction matches
    only within one sub-object and a nested aggregation counts sub-documents; the same docs under an
    `object` mapping cross-match. Also asserts refresh-gated visibility and delete propagation.
    """
    domain = _create_min_domain(ctx, scenario=CHECK)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    obj_index = ctx.unique_name("sim2real-flat-")
    nst_index = ctx.unique_name("sim2real-nest-")
    # One shard keeps terms-aggregation counts exact; refresh_interval -1 turns off the background
    # refresh so pre-refresh invisibility is not a race against the default 1 s timer.
    for index, field_type in ((obj_index, "object"), (nst_index, "nested")):
        status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
            "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0,
                                   "refresh_interval": "-1"}},
            "mappings": {"properties": {
                "case": {"type": "keyword"},
                "tickets": {"type": field_type, "properties": {
                    "assignee": {"type": "keyword"}, "state": {"type": "keyword"}}}}},
        })
        assert status == 200, f"creating the {field_type} index failed with HTTP {status}: {created}"
        assert created.get("acknowledged") is True, (
            f"creating the {field_type} index was not acknowledged: {created!r}"
        )

    # Read the stored mapping back: `nested` silently degrading to `object` would void the test.
    status, mapping = _signed_request(ctx, "GET", f"{base}/{nst_index}/_mapping")
    assert status == 200, f"reading back the nested mapping failed with HTTP {status}: {mapping}"
    stored_type = (mapping.get(nst_index, {}).get("mappings", {})
                   .get("properties", {}).get("tickets", {}).get("type"))
    assert stored_type == "nested", (
        f"the domain stored tickets as {stored_type!r}, not 'nested' -- the isolation claim below "
        f"would be graded against the wrong mapping: {mapping!r}"
    )
    status, settings = _signed_request(ctx, "GET", f"{base}/{nst_index}/_settings")
    assert status == 200, f"reading back the index settings failed with HTTP {status}: {settings}"
    interval = (settings.get(nst_index, {}).get("settings", {})
                .get("index", {}).get("refresh_interval"))
    assert interval == "-1", (
        f"the domain reports refresh_interval {interval!r}, not '-1' -- the pre-refresh visibility "
        f"assertion below would be a race against a background refresh: {settings!r}"
    )

    for index in (obj_index, nst_index):
        for doc_id, doc in DOCS.items():
            status, indexed = _signed_request(ctx, "PUT", f"{base}/{index}/_doc/{doc_id}", body=doc)
            assert status == 201, f"indexing {doc_id} into {index} returned HTTP {status}: {indexed}"
            assert indexed.get("result") == "created", (
                f"indexing {doc_id} into {index} reported result {indexed.get('result')!r}, "
                f"expected 'created'"
            )

    # Visibility is governed by refresh, not by the index call returning 201: none of the documents
    # just written is searchable until the index is refreshed.
    status, unrefreshed = _signed_request(ctx, "POST", f"{base}/{nst_index}/_search",
                                          body={"query": {"match_all": {}}})
    assert status == 200, f"match_all before refresh returned HTTP {status}: {unrefreshed}"
    assert _total(unrefreshed) == 0, (
        f"documents were searchable before _refresh ({_total(unrefreshed)} hits) -- the engine "
        f"published un-refreshed writes to search: {unrefreshed!r}"
    )
    for index in (obj_index, nst_index):
        status, refreshed = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
        assert status == 200, f"refreshing {index} returned HTTP {status}: {refreshed}"

    # The flattened mapping cross-matches: c1 has `alice` and `closed`, in DIFFERENT sub-objects.
    status, flat = _signed_request(ctx, "POST", f"{base}/{obj_index}/_search",
                                   body={"query": CROSS_QUERY, "sort": [{"case": "asc"}]})
    assert status == 200, f"searching the object index returned HTTP {status}: {flat}"
    assert _hit_ids(flat) == ["c1", "c2"], (
        f"an `object` mapping must flatten the array, so alice+closed matches BOTH documents; "
        f"got {_hit_ids(flat)!r} (total {_total(flat)!r})"
    )

    # The nested mapping does not: only c2 holds that pair in ONE sub-object.
    status, nested = _signed_request(
        ctx, "POST", f"{base}/{nst_index}/_search",
        body={"query": {"nested": {"path": "tickets", "query": CROSS_QUERY}}})
    assert status == 200, f"searching the nested index returned HTTP {status}: {nested}"
    assert _hit_ids(nested) == ["c2"], (
        f"a `nested` query must be satisfied inside ONE sub-document, so alice+closed matches c2 "
        f"only; got {_hit_ids(nested)!r} (total {_total(nested)!r})"
    )

    # Same index, same field paths, WITHOUT the nested wrapper: a nested field is invisible to a
    # plain term query, which is the other half of the document-model claim.
    status, unwrapped = _signed_request(ctx, "POST", f"{base}/{nst_index}/_search",
                                        body={"query": CROSS_QUERY})
    assert status == 200, f"unwrapped search on the nested index returned HTTP {status}: {unwrapped}"
    assert _total(unwrapped) == 0, (
        f"a term query on a nested field without a `nested` wrapper must match nothing, because "
        f"the sub-documents are not part of the parent; got {_total(unwrapped)!r}: {unwrapped!r}"
    )

    # The aggregation counts SUB-documents: three tickets across two cases.
    status, agg = _signed_request(ctx, "POST", f"{base}/{nst_index}/_search", body=NESTED_AGG)
    assert status == 200, f"the nested aggregation returned HTTP {status}: {agg}"
    tickets_agg = agg.get("aggregations", {}).get("tickets", {})
    assert tickets_agg.get("doc_count") == 3, (
        f"the nested aggregation must count the 3 ticket sub-documents, not the 2 cases; got "
        f"doc_count={tickets_agg.get('doc_count')!r}: {agg.get('aggregations')!r}"
    )
    buckets = {b["key"]: b["doc_count"] for b in
               tickets_agg.get("by_assignee", {}).get("buckets", [])}
    assert buckets == {"alice": 2, "bob": 1}, (
        f"terms over the nested sub-documents must be alice=2 (one per sub-object) and bob=1; got "
        f"{buckets!r}"
    )

    # Deleting the one document that legitimately matched removes it from every read path, and the
    # sub-document count drops by exactly that document's ticket.
    status, deleted = _signed_request(ctx, "DELETE",
                                      f"{base}/{nst_index}/_doc/c2?refresh=true")
    assert status == 200, f"deleting c2 returned HTTP {status}: {deleted}"
    assert deleted.get("result") == "deleted", (
        f"deleting c2 reported result {deleted.get('result')!r}, expected 'deleted'"
    )
    status, gone = _signed_request(ctx, "GET", f"{base}/{nst_index}/_doc/c2")
    assert status == 404, f"a deleted document must GET 404, got HTTP {status}: {gone}"
    assert gone.get("found") is False, f"GET on the deleted document reported found={gone!r}"
    status, after = _signed_request(
        ctx, "POST", f"{base}/{nst_index}/_search",
        body={"query": {"nested": {"path": "tickets", "query": CROSS_QUERY}}})
    assert status == 200, f"searching after the delete returned HTTP {status}: {after}"
    assert _total(after) == 0, (
        f"the deleted document was still searchable: {_hit_ids(after)!r}"
    )
    status, agg_after = _signed_request(ctx, "POST", f"{base}/{nst_index}/_search", body=NESTED_AGG)
    assert status == 200, f"the nested aggregation after the delete returned HTTP {status}: {agg_after}"
    after_count = agg_after.get("aggregations", {}).get("tickets", {}).get("doc_count")
    assert after_count == 2, (
        f"deleting c2 must remove its 1 ticket sub-document, leaving 2; got {after_count!r}: "
        f"{agg_after.get('aggregations')!r}"
    )

    for index in (obj_index, nst_index):
        _signed_request(ctx, "DELETE", f"{base}/{index}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
