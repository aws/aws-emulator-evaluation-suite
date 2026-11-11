"""osc-deep-opensearch-1-over-replicated-index-yellow-then-green."""
from __future__ import annotations

import http.client
import json
import random
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "osc-deep-opensearch-1-over-replicated-index-yellow-then-green"
GROUP = 'data-plane'
SERVICES = ['opensearch']

# ===== shared domain helpers =====

ENGINE_VERSION = "OpenSearch_2.11"
# Two t3.small.search data nodes, no dedicated cluster manager nodes, no zone awareness, minimum gp3 volume, public
# endpoint with HTTPS enforced. Domains bill per node-hour, so teardown is registered BEFORE create.
CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 2,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
ENDPOINT_OPTIONS = {"EnforceHTTPS": True, "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07"}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# Prefix of the failure raised when a domain endpoint the target published does not answer, so
# that outcome reads as the target's failure rather than as a local network problem.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created, raise on anything else so a
    leaked 24x7 cluster is visible in the run log."""
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


def _create_domain(ctx, *, scenario: str) -> str:
    """Create the two-node HTTPS-enforced domain, cleanup registered BEFORE the create call."""
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(CLUSTER_CONFIG),
        EBSOptions=dict(EBS_OPTIONS),
        DomainEndpointOptions=dict(ENDPOINT_OPTIONS),
        AccessPolicies=_account_access_policy(ctx, domain_name),
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    # CreateDomain is aggressively rate limited per account: jitter, then back off on throttling.
    for attempt in range(12):
        time.sleep(random.uniform(0, 20.0) if attempt == 0 else 6.0 * (1 + attempt) + random.uniform(0, 6.0))
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1350.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep."""
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
    raise AssertionError(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx wired for THIS account, never boto3's ambient chain, and
    sends with stdlib urllib so no third-party HTTP client is needed.
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
        with urllib.request.urlopen(req, timeout=120) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(text)
        except ValueError:
            return exc.code, {"raw": text}
    except (OSError, http.client.HTTPException) as exc:  # the endpoint did not answer at all
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 300.0) -> None:
    """A published Endpoint does not mean the authorizer has the access policy yet; signed requests
    can 403 for a while. Poll a cheap GET until it clears."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status, _ = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            return
        time.sleep(2)
    raise AssertionError(
        f"domain data plane still answered 403 after {timeout_s}s (last status {status})",
    )


def _bulk_load(ctx, base: str, index: str, docs) -> dict:
    """_bulk-index (id, source) pairs and assert the engine reported no per-item error."""
    lines = []
    for doc_id, source in docs:
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps(source))
    status, body = _signed_request(ctx, "POST", f"{base}/_bulk", raw="\n".join(lines) + "\n",
                                   content_type="application/x-ndjson")
    assert status == 200, f"_bulk returned HTTP {status!r}: {body!r}"
    assert body.get("errors") is False, (
        f"_bulk reported per-item errors loading {index!r}: "
        f"{[i for i in body.get('items', []) if 'error' in i.get('index', {})]!r}"
    )
    return body


def _index_health(ctx, base: str, index: str, query: str, *, want, timeout_s: float = 300.0) -> dict:
    """Poll index-scoped _cluster/health with an engine-side wait until ``want(health)`` holds.

    Index-scoped so the managed domain's own system indices cannot move the counts. Bounded by the
    engine's ``timeout`` inside a bounded outer loop, so a target that never settles fails, not hangs.
    """
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        status, last = _signed_request(ctx, "GET", f"{base}/_cluster/health/{index}?{query}&timeout=30s")
        if status == 200 and want(last):
            return last
        time.sleep(3.0)
    raise AssertionError(
        f"index {index!r} health never satisfied the condition within {timeout_s}s "
        f"(query {query!r}, last health {last!r})",
    )


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


# ===== end shared domain helpers =====

_SCENARIO = "osc-over-replicated-index"
_INDEX = "sim2real-overrep"
_DOCS = [(f"doc-{i}", {"n": i, "tag": "even" if i % 2 == 0 else "odd"}) for i in range(6)]


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """On a two-data-node domain an index with two replicas settles YELLOW with one unassigned replica,
    keeps serving _bulk and _search, is explained by _cluster/allocation/explain, and goes GREEN
    once number_of_replicas drops to 1.
    """
    domain = _create_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    # --- over-replicate: 1 primary + 2 replicas on 2 data nodes ---------------------------------
    status, created = _signed_request(ctx, "PUT", f"{base}/{_INDEX}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 2}},
        "mappings": {"properties": {"n": {"type": "integer"}, "tag": {"type": "keyword"}}}})
    assert status == 200, f"creating index {_INDEX!r} returned HTTP {status!r}: {created!r}"
    assert created.get("acknowledged") is True, f"index create not acknowledged: {created!r}"

    # Settle: primary + one replica active, nothing initializing, so the remaining unassigned copy
    # is the one that CANNOT be placed rather than one still being placed.
    yellow = _index_health(
        ctx, base, _INDEX,
        "wait_for_status=yellow&wait_for_active_shards=2&wait_for_no_initializing_shards=true",
        want=lambda h: h.get("timed_out") is False and h.get("active_shards") == 2
        and h.get("initializing_shards") == 0)
    assert yellow.get("status") == "yellow", (
        f"a 1-primary 2-replica index on 2 data nodes reports status {yellow.get('status')!r}, "
        f"expected yellow -- three copies cannot fit on two nodes: {yellow!r}"
    )
    assert yellow.get("number_of_data_nodes") == 2, (
        f"_cluster/health reports {yellow.get('number_of_data_nodes')!r} data nodes for an "
        f"InstanceCount of 2: {yellow!r}"
    )
    assert yellow.get("active_primary_shards") == 1, (
        f"active_primary_shards is {yellow.get('active_primary_shards')!r}, expected 1: {yellow!r}"
    )
    assert yellow.get("active_shards") == 2, (
        f"active_shards is {yellow.get('active_shards')!r}, expected 2 (primary + the one replica "
        f"the second node can hold): {yellow!r}"
    )
    assert yellow.get("unassigned_shards") == 1, (
        f"unassigned_shards is {yellow.get('unassigned_shards')!r}, expected exactly 1 -- the "
        f"second replica has no node it may legally occupy: {yellow!r}"
    )

    # --- the data plane still works while yellow -------------------------------------------------
    bulk = _bulk_load(ctx, base, _INDEX, _DOCS)
    assert len(bulk.get("items", [])) == len(_DOCS), (
        f"_bulk returned {len(bulk.get('items', []))!r} items for {len(_DOCS)} documents: {bulk!r}"
    )
    status, _ = _signed_request(ctx, "POST", f"{base}/{_INDEX}/_refresh")
    assert status == 200, f"_refresh on a yellow index returned HTTP {status!r}"
    status, found = _signed_request(ctx, "POST", f"{base}/{_INDEX}/_search", body={
        "query": {"term": {"tag": "even"}}, "size": 10, "sort": [{"n": "asc"}]})
    assert status == 200, f"_search on a yellow index returned HTTP {status!r}: {found!r}"
    assert _total(found) == 3, f"_search for tag=even counted {_total(found)!r}, expected 3: {found!r}"
    got = [h["_id"] for h in found.get("hits", {}).get("hits", [])]
    assert got == ["doc-0", "doc-2", "doc-4"], f"_search returned ids {got!r}, expected doc-0/2/4"

    still = _index_health(ctx, base, _INDEX, "wait_for_status=yellow",
                          want=lambda h: h.get("timed_out") is False)
    assert (still.get("status"), still.get("unassigned_shards")) == ("yellow", 1), (
        f"after writes the index reports status {still.get('status')!r} with "
        f"{still.get('unassigned_shards')!r} unassigned shards, expected yellow with 1: {still!r}"
    )

    # --- allocation/explain names the stranded replica ------------------------------------------
    status, explain = _signed_request(ctx, "GET", f"{base}/_cluster/allocation/explain", body={
        "index": _INDEX, "shard": 0, "primary": False})
    assert status == 200, f"_cluster/allocation/explain returned HTTP {status!r}: {explain!r}"
    assert (explain.get("index"), explain.get("shard"), explain.get("primary")) == (_INDEX, 0, False), (
        f"allocation/explain described index={explain.get('index')!r} shard={explain.get('shard')!r} "
        f"primary={explain.get('primary')!r}, expected the replica of {_INDEX!r} shard 0: {explain!r}"
    )
    assert explain.get("current_state") == "unassigned", (
        f"the explained replica is {explain.get('current_state')!r}, expected unassigned: {explain!r}"
    )
    assert explain.get("can_allocate") == "no", (
        f"can_allocate is {explain.get('can_allocate')!r}, expected 'no' -- no node may take a "
        f"third copy: {explain!r}"
    )
    decisions = explain.get("node_allocation_decisions") or []
    assert len(decisions) == 2, (
        f"allocation/explain carries {len(decisions)!r} node decisions, expected one per data node "
        f"(2): {decisions!r}"
    )
    for d in decisions:
        same = [x for x in d.get("deciders", []) if x.get("decider") == "same_shard"]
        assert same and same[0].get("decision") == "NO", (
            f"node {d.get('node_name')!r} does not refuse the replica on the same_shard decider "
            f"(it already holds a copy): {d!r}"
        )

    # --- lower the replica count: the cluster must go green --------------------------------------
    status, upd = _signed_request(ctx, "PUT", f"{base}/{_INDEX}/_settings",
                                  body={"index": {"number_of_replicas": 1}})
    assert status == 200 and upd.get("acknowledged") is True, (
        f"PUT _settings number_of_replicas=1 returned HTTP {status!r}: {upd!r}"
    )
    green = _index_health(ctx, base, _INDEX, "wait_for_status=green",
                          want=lambda h: h.get("timed_out") is False)
    assert green.get("status") == "green", (
        f"after lowering replicas to 1 the index reports {green.get('status')!r}, expected green: {green!r}"
    )
    assert green.get("unassigned_shards") == 0, (
        f"unassigned_shards is {green.get('unassigned_shards')!r} after lowering replicas, "
        f"expected 0: {green!r}"
    )
    assert green.get("active_shards") == 2, (
        f"active_shards is {green.get('active_shards')!r} after lowering replicas, expected 2: {green!r}"
    )
    status, count = _signed_request(ctx, "GET", f"{base}/{_INDEX}/_count")
    assert status == 200 and count.get("count") == len(_DOCS), (
        f"_count after going green returned HTTP {status!r} {count!r}, expected {len(_DOCS)} "
        f"documents -- the replica change must not lose writes made while yellow"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
