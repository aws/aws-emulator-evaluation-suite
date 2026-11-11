"""msearch-responses-are-positional-and-isolate-a-failing-slot."""
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

CHECK = "msearch-responses-are-positional-and-isolate-a-failing-slot"
GROUP = 'ordering'
SERVICES = ['opensearch']

# ===== shared domain helpers =====

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

# Prefix of the failure raised when a domain endpoint the target published does not answer, so
# that outcome reads as the target's failure rather than as a local network problem.
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
        # An HTTP status (above) is data the caller asserts on; a transport failure is not, and
        # urllib reports it in wording that reads as a local network problem. The endpoint here was
        # published by the target itself, so failing to answer on it is the target's failure.
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


# ===== end shared domain helpers =====

_SCENARIO = "msearch-positional"
_INDEX_A = "sim2real-behav-ms-a"
_INDEX_B = "sim2real-behav-ms-b"
# Never created. The slot that names it must fail alone.
_ABSENT = "sim2real-behav-ms-absent"


def _bulk_load(ctx, base: str, index: str, docs) -> None:
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


def _create_index(ctx, base: str, index: str) -> None:
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"group": {"type": "keyword"}}}})
    assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/{index}"))


def _msearch(ctx, base: str, slots):
    """Submit (index, query) pairs as NDJSON and return the parsed responses array."""
    lines = []
    for index, query in slots:
        lines.append(json.dumps({"index": index}))
        lines.append(json.dumps({"track_total_hits": True, "size": 10, "query": query}))
    status, body = _signed_request(ctx, "POST", f"{base}/_msearch",
                                   raw="\n".join(lines) + "\n",
                                   content_type="application/x-ndjson")
    return status, body


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """`_msearch` answers with one response per request line, in submission order -- proved by
    resubmitting the same four requests reversed -- and a slot naming an absent index fails alone
    with `index_not_found_exception` inside an overall HTTP 200, its neighbours still returning hits.

    Reference: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-operations.html
    """
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    _create_index(ctx, base, _INDEX_A)
    _create_index(ctx, base, _INDEX_B)
    _bulk_load(ctx, base, _INDEX_A, [("a0", {"group": "a"}), ("a1", {"group": "a"}),
                                     ("a2", {"group": "a"})])
    _bulk_load(ctx, base, _INDEX_B, [("b0", {"group": "b"})])

    # Four deliberately DIFFERENT answers, so no two slots can be confused with each other:
    # 1 hit, 3 hits, a failure, 0 hits.
    slots = [
        (_INDEX_B, {"match_all": {}}),
        (_INDEX_A, {"match_all": {}}),
        (_ABSENT, {"match_all": {}}),
        (_INDEX_A, {"term": {"group": "no-such-group"}}),
    ]

    status, body = _msearch(ctx, base, slots)
    assert status == 200, (
        f"_msearch with one failing slot returned overall HTTP {status!r}, expected 200 -- a per-slot "
        f"failure must not fail the whole multi-search: {body!r}")
    responses = body["responses"]
    assert len(responses) == len(slots), (
        f"_msearch returned {len(responses)!r} responses for {len(slots)!r} request lines, expected "
        f"one per line: {body!r}")

    assert "error" not in responses[0], (
        f"slot 0 (index {_INDEX_B!r}) carries an error, expected hits: {responses[0]!r}")
    assert _total(responses[0]) == 1, (
        f"slot 0 (index {_INDEX_B!r}) reports {_total(responses[0])!r} hits, expected 1: "
        f"{responses[0]!r}")
    assert [h["_id"] for h in responses[0]["hits"]["hits"]] == ["b0"], (
        f"slot 0 returned ids {[h['_id'] for h in responses[0]['hits']['hits']]!r}, expected ['b0'] "
        f"-- the answer in slot 0 must come from the index named on request line 0")

    assert "error" not in responses[1], (
        f"slot 1 (index {_INDEX_A!r}) carries an error, expected hits: {responses[1]!r}")
    assert _total(responses[1]) == 3, (
        f"slot 1 (index {_INDEX_A!r}) reports {_total(responses[1])!r} hits, expected 3: "
        f"{responses[1]!r}")

    assert "error" in responses[2], (
        f"slot 2 named the absent index {_ABSENT!r} and returned no error: {responses[2]!r} -- "
        f"silently answering zero hits for an index that does not exist is the over-permissive "
        f"failure this slot exists to catch")
    assert _error_type(responses[2]) == "index_not_found_exception", (
        f"slot 2 reports error type {_error_type(responses[2])!r}, expected "
        f"'index_not_found_exception': {responses[2]!r}")
    assert responses[2].get("status") == 404, (
        f"slot 2 reports status {responses[2].get('status')!r}, expected 404: {responses[2]!r}")

    assert "error" not in responses[3], (
        f"slot 3 (a term query matching nothing) carries an error, expected an empty result set: "
        f"{responses[3]!r}")
    assert _total(responses[3]) == 0, (
        f"slot 3 reports {_total(responses[3])!r} hits for a term that matches no document, expected "
        f"0: {responses[3]!r}")

    # The reversal leg: the identical four requests, submitted backwards. Every answer must move with
    # its request line.
    status, reversed_body = _msearch(ctx, base, list(reversed(slots)))
    assert status == 200, (
        f"the reversed _msearch returned overall HTTP {status!r}, expected 200: {reversed_body!r}")
    reversed_responses = reversed_body["responses"]
    assert len(reversed_responses) == len(slots), (
        f"the reversed _msearch returned {len(reversed_responses)!r} responses for {len(slots)!r} "
        f"request lines: {reversed_body!r}")
    assert _total(reversed_responses[3]) == 1, (
        f"after reversing the request lines, the last slot reports {_total(reversed_responses[3])!r} "
        f"hits, expected the 1 hit that index {_INDEX_B!r} answered in slot 0 before -- the response "
        f"array must be positional, not ordered by content or completion")
    assert _total(reversed_responses[2]) == 3, (
        f"after reversing, slot 2 reports {_total(reversed_responses[2])!r} hits, expected 3 from "
        f"index {_INDEX_A!r}: {reversed_responses[2]!r}")
    assert _error_type(reversed_responses[1]) == "index_not_found_exception", (
        f"after reversing, slot 1 (now the absent index) reports error type "
        f"{_error_type(reversed_responses[1])!r}, expected 'index_not_found_exception': "
        f"{reversed_responses[1]!r}")
    assert "error" not in reversed_responses[0] and _total(reversed_responses[0]) == 0, (
        f"after reversing, slot 0 (the term query matching nothing) reports "
        f"{reversed_responses[0]!r}, expected an error-free empty result set")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
