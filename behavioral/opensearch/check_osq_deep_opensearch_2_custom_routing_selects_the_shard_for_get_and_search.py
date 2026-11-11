"""osq-deep-opensearch-2-custom-routing-selects-the-shard-for-get-and-search."""
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

CHECK = "osq-deep-opensearch-2-custom-routing-selects-the-shard-for-get-and-search"
GROUP = "data-plane"
SERVICES = ["opensearch"]

# ===== shared helpers (self-contained) =====

ENGINE_VERSION = "OpenSearch_2.19"
# Smallest legal single-node topology: a domain bills per node-hour, so this provisions the cheapest
# legal cluster and registers teardown BEFORE the create call.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# An endpoint data-plane FAIL marker: the harness scores a detail containing this string as a real
# fidelity failure ahead of its connection-error / not-implemented classification, so a domain
# endpoint the target published and then failed to answer on is graded as a failure rather than
# treated as an environment problem.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created / already deleted."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _account_access_policy(ctx, domain_name: str) -> str:
    """Resource policy letting THIS account's principals use the data plane. The account comes from
    STS, never a literal, so the same check passes in any account."""
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


def _create_min_domain(ctx) -> str:
    """Create the cheapest legal domain, cleanup registered BEFORE the create call."""
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-osq-").lower()[:28].rstrip("-")
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        AccessPolicies=_account_access_policy(ctx, domain_name),
        # Tagged at creation so account cleanup can find it if teardown is interrupted.
        TagList=[{"Key": "sim2real", "Value": CHECK[:256]}],
    )
    # CreateDomain is rate limited per account: jitter, then a bounded back-off on throttling only.
    for attempt in range(10):
        if attempt == 0:
            time.sleep(random.uniform(0, 5.0))
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    raise AssertionError(f"CreateDomain for {domain_name} still throttled after 10 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1500.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep."""
    osc = ctx.client("opensearch")
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2.0)
    raise AssertionError(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')!r}, Endpoint={last.get('Endpoint')!r})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx wires for this account (not boto3's ambient chain): signing as
    the wrong principal makes the domain's account-scoped policy 403 the request.
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
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # the endpoint did not answer at all
        # An HTTP status is data the caller asserts on; a transport failure is not. The endpoint was
        # published by the target itself, so failing to answer on it is the target's failure.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 420.0) -> None:
    """Processing=False + an Endpoint does NOT mean the data-plane authorizer has the access policy
    yet; signed requests can 403 for a while. Poll a cheap GET until it clears."""
    deadline = time.monotonic() + timeout_s
    status, body = None, None
    while time.monotonic() < deadline:
        status, body = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            break
        time.sleep(2.0)
    assert status == 200, f"signed GET / on the domain endpoint returned {status!r}: {body!r}"


def _error_type(payload) -> str:
    """OpenSearch engine errors carry {'error': {'type': ..., 'reason': ...}, 'status': n}.

    Never returns a falsy sentinel for a success body: a 2xx has no 'error' and yields the literal
    '<no error>', which cannot be confused with an engine error type."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type"))
    return "<no error>"


def _total(result) -> int:
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


def _hit_ids(result) -> list:
    return [h["_id"] for h in result["hits"]["hits"]]


# ===== end shared helpers =====

_ROUTING = "k"
_CANDIDATES = [f"c{n}" for n in range(32)]


def _shard_for(ctx, base: str, index: str, routing: str) -> int:
    """The shard the TARGET says a routing value resolves to. Derived from the target, never from a
    locally computed hash, so a faithful emulator using any routing function still passes."""
    status, body = _signed_request(ctx, "GET", f"{base}/{index}/_search_shards?routing={routing}")
    assert status == 200, f"_search_shards?routing={routing} returned HTTP {status!r}: {body!r}"
    groups = body.get("shards", [])
    assert len(groups) == 1, (
        f"_search_shards with routing {routing!r} must resolve to exactly one shard group, got "
        f"{groups!r}")
    return groups[0][0]["shard"]


def _search(ctx, base: str, path: str, query: dict) -> dict:
    status, body = _signed_request(ctx, "POST", f"{base}{path}", body=query)
    assert status == 200, f"POST {path} returned HTTP {status!r}: {body!r}"
    return body


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Custom routing pins a document to one shard: a plain GET/DELETE by id (which hashes to a
    different shard) misses it, while a routed GET, a same-shard routing value, and an un-routed
    match_all all reach the pinned shard instead of filtering on the stored `_routing` value.
    """
    domain = _create_min_domain(ctx)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = ctx.unique_name("sim2real-osq-rt-").lower()
    status, body = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 2, "number_of_replicas": 0}},
        "mappings": {"properties": {"v": {"type": "integer"}}}})
    assert status == 200 and body.get("acknowledged") is True, (
        f"creating 2-shard index {index!r} returned HTTP {status!r}: {body!r}")
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/{index}"))
    status, settings = _signed_request(ctx, "GET", f"{base}/{index}/_settings")
    assert status == 200 and settings[index]["settings"]["index"]["number_of_shards"] == "2", (
        f"index must report 2 primary shards: HTTP {status!r} {settings!r}")

    home = _shard_for(ctx, base, index, _ROUTING)
    shard_of = {c: _shard_for(ctx, base, index, c) for c in _CANDIDATES}
    # Routing by _id is routing by the id string, so an id on the other shard is a candidate whose
    # routing value resolves away from `k`; same for the "other" routing value used by _search.
    away = [c for c in _CANDIDATES if shard_of[c] != home]
    same = [c for c in _CANDIDATES if shard_of[c] == home]
    assert len(away) >= 2 and same, (
        f"over {len(_CANDIDATES)} candidate values the target placed none (or too few) on each of "
        f"the 2 shards -- routing is not distributing: home={home!r} shard_of={shard_of!r}")
    doc_id, other_routing, same_shard_routing = away[0], away[1], same[0]

    status, body = _signed_request(ctx, "PUT", f"{base}/{index}/_doc/{doc_id}?routing={_ROUTING}&refresh=true",
                                   body={"v": 1})
    assert status == 201 and body.get("result") == "created", (
        f"routed index of {doc_id!r} returned HTTP {status!r}: {body!r}")

    # Plain GET routes by the id, which lands on the other shard: not found.
    status, body = _signed_request(ctx, "GET", f"{base}/{index}/_doc/{doc_id}")
    assert status == 404 and body.get("found") is False, (
        f"GET {doc_id!r} WITHOUT routing must 404 (id hashes to shard {shard_of[doc_id]!r}, the "
        f"document lives on shard {home!r}); got HTTP {status!r}: {body!r}")

    status, body = _signed_request(ctx, "GET", f"{base}/{index}/_doc/{doc_id}?routing={_ROUTING}")
    assert status == 200 and body.get("found") is True and body.get("_source") == {"v": 1}, (
        f"GET with routing={_ROUTING!r} must return the source; got HTTP {status!r}: {body!r}")
    assert body.get("_routing") == _ROUTING, f"GET reports _routing {body.get('_routing')!r}"

    status, body = _signed_request(ctx, "GET", f"{base}/{index}/_doc/{doc_id}?routing={same_shard_routing}")
    assert status == 200 and body.get("found") is True, (
        f"routing {same_shard_routing!r} resolves to the document's shard {home!r}, so GET must find "
        f"it -- routing selects a shard, it does not filter on _routing; got HTTP {status!r}: {body!r}")
    assert body.get("_routing") == _ROUTING, (
        f"the stored _routing must still be {_ROUTING!r}, got {body.get('_routing')!r}")

    missed = _search(ctx, base, f"/{index}/_search?routing={other_routing}", {"query": {"match_all": {}}})
    assert _total(missed) == 0 and missed["_shards"]["total"] == 1, (
        f"_search?routing={other_routing!r} must search exactly one shard (the other one) and miss "
        f"the document: total {_total(missed)!r} shards {missed['_shards']!r}")

    found = _search(ctx, base, f"/{index}/_search", {"query": {"match_all": {}}})
    assert found["_shards"]["total"] == 2, f"un-routed search must fan out to 2 shards: {found['_shards']!r}"
    assert [(h["_id"], h.get("_routing")) for h in found["hits"]["hits"]] == [(doc_id, _ROUTING)], (
        f"un-routed match_all must return exactly {doc_id!r} with _routing {_ROUTING!r}, got "
        f"{[(h['_id'], h.get('_routing')) for h in found['hits']['hits']]!r}")

    # An un-routed DELETE also goes to the id's shard: it finds nothing and removes nothing.
    status, body = _signed_request(ctx, "DELETE", f"{base}/{index}/_doc/{doc_id}?refresh=true")
    assert status == 404 and body.get("result") == "not_found", (
        f"DELETE {doc_id!r} without routing must report not_found; got HTTP {status!r}: {body!r}")
    status, body = _signed_request(ctx, "GET", f"{base}/{index}/_doc/{doc_id}?routing={_ROUTING}")
    assert status == 200 and body.get("found") is True, (
        f"the document must survive the un-routed DELETE; routed GET returned HTTP {status!r}: {body!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
