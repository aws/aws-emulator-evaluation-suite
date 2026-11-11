"""update-by-query-script-touches-exactly-the-matched-documents."""
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

CHECK = "update-by-query-script-touches-exactly-the-matched-documents"
GROUP = 'data-plane'
SERVICES = ['opensearch']

# ===== shared helpers (self-contained) =====

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology. Domains bill per node-hour and leaked domains were a real
# cost-leak class, so this provisions the cheapest legal cluster and registers teardown BEFORE create.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# An endpoint data-plane FAIL marker: a domain endpoint the target published and then failed to
# answer on scores as a real fidelity failure, never as an environment problem.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


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


def _create_min_domain(ctx, *, scenario: str, **overrides) -> str:
    """Create the cheapest legal domain, cleanup registered BEFORE the create call."""
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
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
    time.sleep(random.uniform(0, 20.0))
    for attempt in range(12):
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1200.0) -> str:
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
    raise AssertionError(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx wired for THIS account (not boto3's ambient chain):
    signing as the wrong principal makes the domain's account-scoped policy 403 the request.
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
        # An HTTP status (above) is data the caller asserts on; a transport failure is not. The
        # endpoint here was published by the target itself, so failing to answer on it is the
        # target's failure.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


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
    raise AssertionError(
        f"domain data plane still answered 403 after {timeout_s}s (last status {status})",
    )


def _error_type(payload) -> str:
    """OpenSearch engine errors carry {'error': {'type': ..., 'reason': ...}, 'status': n}."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type") or "")
    return ""


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


def _hit_ids(result) -> list:
    return [h["_id"] for h in result["hits"]["hits"]]


# ===== end shared helpers =====

_SCENARIO = "update-by-query-exactness"
# Two groups in one index. Only group "a" is ever matched, so group "b" is a control group living in
# the same shard at the same instant: a target that applies the script to the whole index fails on it.
_DOCS = [
    ("u0", {"group": "a", "n": 0}),
    ("u1", {"group": "a", "n": 1}),
    ("u2", {"group": "a", "n": 2}),
    ("u3", {"group": "a", "n": 3}),
    ("b0", {"group": "b", "n": 100}),
    ("b1", {"group": "b", "n": 101}),
]


def _bulk_load(ctx, base: str, index: str, docs) -> None:
    """_bulk-index (id, source) pairs and assert the engine reported no per-item error."""
    lines = []
    for doc_id, source in docs:
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps(source))
    status, body = _signed_request(ctx, "POST", f"{base}/_bulk?refresh=true",
                                   raw="\n".join(lines) + "\n",
                                   content_type="application/x-ndjson")
    assert status == 200, f"_bulk returned HTTP {status!r}, expected 200: {body!r}"
    assert body.get("errors") is False, (
        f"_bulk reported per-item errors loading {index!r}: "
        f"{[i for i in body.get('items', []) if 'error' in i.get('index', {})]!r}")


def _search(ctx, base: str, index: str, query: dict) -> dict:
    status, result = _signed_request(
        ctx, "POST", f"{base}/{index}/_search",
        body={"size": 20, "track_total_hits": True, "version": True, "query": query})
    assert status == 200, f"_search on {index!r} returned HTTP {status!r}, expected 200: {result!r}"
    return result


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """`_update_by_query` with a painless script reports exact server-computed counts for only the
    matched documents, rewrites exactly their `_source`s and `_version`s, and leaves a same-index
    control group untouched; `_delete_by_query` then removes exactly a compound-query subset.

    Reference: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-operations.html
    """
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = "sim2real-behav-ubq"
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"group": {"type": "keyword"}, "n": {"type": "integer"},
                                    "touched": {"type": "integer"}}}})
    assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/{index}"))
    _bulk_load(ctx, base, index, _DOCS)

    # POSITIVE CONTROL: all six documents are there, and none carries the field the script will add.
    baseline = _search(ctx, base, index, {"match_all": {}})
    assert _total(baseline) == len(_DOCS), (
        f"_search reports {_total(baseline)!r} documents after loading {len(_DOCS)!r}, expected "
        f"{len(_DOCS)!r}: hits={baseline.get('hits')!r}")
    pre_versions = {h["_id"]: h["_version"] for h in baseline["hits"]["hits"]}
    assert all("touched" not in h["_source"] for h in baseline["hits"]["hits"]), (
        f"a freshly loaded document already carries a 'touched' field, so the update below would "
        f"prove nothing: {[h['_source'] for h in baseline['hits']['hits']]!r}")

    status, ubq = _signed_request(
        ctx, "POST", f"{base}/{index}/_update_by_query?refresh=true",
        body={"query": {"term": {"group": "a"}},
              "script": {"lang": "painless", "source": "ctx._source.touched = ctx._source.n * 10"}})
    assert status == 200, f"_update_by_query returned HTTP {status!r}, expected 200: {ubq!r}"
    assert ubq.get("failures") == [], (
        f"_update_by_query reported failures {ubq.get('failures')!r}, expected none: {ubq!r}")
    assert ubq.get("total") == 4, (
        f"_update_by_query reports total {ubq.get('total')!r}, expected 4 -- the query matches the "
        f"four group 'a' documents and nothing else: {ubq!r}")
    assert ubq.get("updated") == 4, (
        f"_update_by_query reports updated {ubq.get('updated')!r}, expected 4: {ubq!r}")
    assert ubq.get("version_conflicts") == 0, (
        f"_update_by_query reports version_conflicts {ubq.get('version_conflicts')!r}, expected 0 -- "
        f"nothing else is writing to this index: {ubq!r}")
    assert ubq.get("noops") == 0, (
        f"_update_by_query reports noops {ubq.get('noops')!r}, expected 0 -- every matched document "
        f"gains a new field, so none of them can be a no-op: {ubq!r}")

    # TERMINAL READ at the destination, through a different operation: the values the script computed.
    updated = _search(ctx, base, index, {"term": {"group": "a"}})
    assert _total(updated) == 4, (
        f"_search for group 'a' returns {_total(updated)!r} documents, expected 4: "
        f"hits={updated.get('hits')!r}")
    for hit in updated["hits"]["hits"]:
        source = hit["_source"]
        assert source["touched"] == source["n"] * 10, (
            f"document {hit['_id']!r} holds touched {source.get('touched')!r} for n {source['n']!r}, "
            f"expected {source['n'] * 10!r} -- the painless script did not run over this document: "
            f"{source!r}")
        assert hit["_version"] == pre_versions[hit["_id"]] + 1, (
            f"document {hit['_id']!r} reports _version {hit['_version']!r}, expected "
            f"{pre_versions[hit['_id']] + 1!r} (its pre-update version plus one) -- an update that "
            f"does not advance the version is not a write")

    # CONTROL GROUP, same index, same instant: untouched and unversioned.
    control = _search(ctx, base, index, {"term": {"group": "b"}})
    assert _total(control) == 2, (
        f"_search for group 'b' returns {_total(control)!r} documents, expected 2: "
        f"hits={control.get('hits')!r}")
    for hit in control["hits"]["hits"]:
        assert "touched" not in hit["_source"], (
            f"control document {hit['_id']!r} was modified by an _update_by_query whose query did not "
            f"match it: {hit['_source']!r}")
        assert hit["_version"] == pre_versions[hit["_id"]], (
            f"control document {hit['_id']!r} reports _version {hit['_version']!r}, expected the "
            f"unchanged {pre_versions[hit['_id']]!r}")

    # _delete_by_query must remove exactly the compound-query subset: group 'a' AND n >= 2.
    status, dbq = _signed_request(
        ctx, "POST", f"{base}/{index}/_delete_by_query?refresh=true",
        body={"query": {"bool": {"filter": [{"term": {"group": "a"}},
                                            {"range": {"n": {"gte": 2}}}]}}})
    assert status == 200, f"_delete_by_query returned HTTP {status!r}, expected 200: {dbq!r}"
    assert dbq.get("failures") == [], (
        f"_delete_by_query reported failures {dbq.get('failures')!r}, expected none: {dbq!r}")
    assert dbq.get("deleted") == 2, (
        f"_delete_by_query reports deleted {dbq.get('deleted')!r}, expected 2 -- only u2 and u3 are "
        f"in group 'a' with n >= 2; the group 'b' documents have larger n and must be excluded by the "
        f"group filter: {dbq!r}")
    assert dbq.get("total") == 2, (
        f"_delete_by_query reports total {dbq.get('total')!r}, expected 2: {dbq!r}")

    survivors = _search(ctx, base, index, {"match_all": {}})
    assert sorted(h["_id"] for h in survivors["hits"]["hits"]) == ["b0", "b1", "u0", "u1"], (
        f"the surviving ids are {sorted(h['_id'] for h in survivors['hits']['hits'])!r}, expected "
        f"['b0', 'b1', 'u0', 'u1'] -- the complement of the deleted subset")
    status, counted = _signed_request(ctx, "GET", f"{base}/{index}/_count")
    assert status == 200 and counted["count"] == 4, (
        f"_count reports {counted.get('count')!r} after deleting 2 of 6, expected 4: {counted!r}")
    status, gone = _signed_request(ctx, "GET", f"{base}/{index}/_doc/u3")
    assert status == 404, (
        f"GET of the deleted document u3 returned HTTP {status!r}, expected 404: {gone!r}")
    assert gone.get("found") is False, (
        f"GET of the deleted document u3 reports found={gone.get('found')!r}, expected False: "
        f"{gone!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
