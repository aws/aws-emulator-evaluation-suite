"""knn-vector-query-nearest-neighbour-ordering."""
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

CHECK = "knn-vector-query-nearest-neighbour-ordering"
GROUP = 'data-plane'
SERVICES = ['opensearch']

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


def _create_min_domain(ctx, *, access_policies=None, **overrides) -> str:
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
        TagList=[{"Key": "sim2real", "Value": "behavioral-check"}],
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: jitter before the first attempt,
    # then backoff on throttling. Both delays live inside the bounded (12-attempt) retry loop.
    for attempt in range(12):
        try:
            if attempt == 0:
                time.sleep(random.uniform(0, 20.0))
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
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


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1800.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep."""
    osc = ctx.client("opensearch")
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        last = _domain_status(osc, domain_name, deadline)
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2.0)
    raise AssertionError(
        f"domain {domain_name} never became searchable within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx wired for THIS account (not boto3's ambient chain):
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
        time.sleep(2.0)
    raise AssertionError(f"domain data plane still 403 after {timeout_s}s (last status {status})")


# Four vectors on a single axis so the true k-NN ordering is unambiguous and hand-checkable.
# Query vector is [1.1, 0, 0, 0]; L2 distances are at-1=0.1, at-2=0.9, at-0=1.1, at-10=8.9.
VECTORS = {
    "at-0": [0.0, 0.0, 0.0, 0.0],
    "at-1": [1.0, 0.0, 0.0, 0.0],
    "at-2": [2.0, 0.0, 0.0, 0.0],
    "at-10": [10.0, 0.0, 0.0, 0.0],
}
QUERY_VECTOR = [1.1, 0.0, 0.0, 0.0]
EXPECTED_TOP3 = ["at-1", "at-2", "at-0"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """REAL BACKEND: a knn_vector index answers a k-NN query with the true nearest neighbours,
    nearest-first, with strictly decreasing scores -- a stub that stores documents and returns
    them in insertion order cannot rank by vector distance.
    """
    domain = _create_min_domain(ctx)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = "sim2real-behav-knn"
    # index.knn=true is what activates the k-NN plugin for this index; a single shard with no
    # replicas keeps the search deterministic (no per-shard score variance).
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"knn": True, "number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {
            "label": {"type": "keyword"},
            "embedding": {
                "type": "knn_vector",
                "dimension": 4,
                "method": {"name": "hnsw", "space_type": "l2", "engine": "lucene"},
            },
        }},
    })
    assert status in (200, 201), f"creating knn index failed with HTTP {status}: {created}"
    assert created.get("acknowledged") is True, f"index creation not acknowledged: {created}"

    # The mapping must round-trip as a real knn_vector field, not be silently downgraded.
    status, mapping = _signed_request(ctx, "GET", f"{base}/{index}/_mapping")
    assert status == 200, f"_mapping read failed with HTTP {status}: {mapping}"
    props = mapping.get(index, {}).get("mappings", {}).get("properties", {})
    assert props.get("embedding", {}).get("type") == "knn_vector", (
        f"embedding field is not knn_vector in the stored mapping: {props.get('embedding')}"
    )
    assert props.get("embedding", {}).get("dimension") == 4, (
        f"knn_vector dimension not preserved: {props.get('embedding')}"
    )

    for doc_id, vector in VECTORS.items():
        status, body = _signed_request(
            ctx, "PUT", f"{base}/{index}/_doc/{doc_id}",
            body={"label": doc_id, "embedding": vector},
        )
        assert status in (200, 201), f"indexing {doc_id} failed with HTTP {status}: {body}"

    status, refreshed = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"_refresh failed with HTTP {status}: {refreshed}"

    status, result = _signed_request(ctx, "POST", f"{base}/{index}/_search", body={
        "size": 3,
        "query": {"knn": {"embedding": {"vector": QUERY_VECTOR, "k": 3}}},
    })
    assert status == 200, f"k-NN _search failed with HTTP {status}: {result}"
    hits = result.get("hits", {}).get("hits", [])
    assert len(hits) == 3, f"expected exactly 3 k-NN hits for k=3, got {len(hits)}: {hits}"
    got_order = [hit.get("_id") for hit in hits]
    assert got_order == EXPECTED_TOP3, (
        f"k-NN neighbours returned in the wrong order: expected {EXPECTED_TOP3}, got {got_order} "
        f"(query vector {QUERY_VECTOR})"
    )
    scores = [hit.get("_score") for hit in hits]
    assert all(isinstance(s, (int, float)) for s in scores), f"missing _score on hits: {scores}"
    assert scores[0] > scores[1] > scores[2], (
        f"k-NN scores must strictly decrease with distance, got {scores} for {got_order}"
    )
    assert hits[0].get("_source", {}).get("label") == "at-1", (
        f"nearest neighbour _source not returned: {hits[0].get('_source')}"
    )

    # k semantics: k=1 must return exactly the single nearest neighbour, not the whole index.
    status, one = _signed_request(ctx, "POST", f"{base}/{index}/_search", body={
        "size": 10,
        "query": {"knn": {"embedding": {"vector": QUERY_VECTOR, "k": 1}}},
    })
    assert status == 200, f"k=1 _search failed with HTTP {status}: {one}"
    one_hits = one.get("hits", {}).get("hits", [])
    assert [h.get("_id") for h in one_hits] == ["at-1"], (
        f"k=1 must return only the nearest neighbour, got {[h.get('_id') for h in one_hits]}"
    )

    status, deleted = _signed_request(ctx, "DELETE", f"{base}/{index}")
    assert status == 200, f"deleting knn index failed with HTTP {status}: {deleted}"

    # The delete must be provable, not just fired-and-forgotten: an independent read on the
    # same index now returns the specific not-found error, not a stale 200.
    status, gone = _signed_request(ctx, "GET", f"{base}/{index}")
    assert status == 404, f"deleted index still reachable: HTTP {status}: {gone}"
    assert gone.get("error", {}).get("type") == "index_not_found_exception", (
        f"deleted index lookup did not return index_not_found_exception: {gone}"
    )

    # A mutation on the dead index also fails, not just a read.
    status, closed = _signed_request(ctx, "POST", f"{base}/{index}/_close")
    assert status == 404, f"closing deleted index expected HTTP 404, got {status}: {closed}"
    assert closed.get("error", {}).get("type") == "index_not_found_exception", (
        f"closing deleted index did not return index_not_found_exception: {closed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
