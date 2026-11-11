"""reindex-into-keyword-mapping-preserves-documents-and-enables-term-match."""
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

CHECK = "reindex-into-keyword-mapping-preserves-documents-and-enables-term-match"
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
    # CreateDomain is aggressively rate limited per account: back off on throttling, with jitter
    # so concurrent callers don't retry in lockstep.
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
    """Poll to Processing=False AND a published Endpoint; never a bare sleep.

    The budget is sized so the whole check fits an 1800 s runner timeout; provisioning this
    topology takes ~680-850 s.
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
    raise AssertionError(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx wired for the target account (not boto3's ambient chain):
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
    """OpenSearch engine errors carry {'error': {'type': ..., 'reason': ...}, 'status': n}.

    Structural, single-valued and never an alternation: the engine puts the wrapper type in
    ``error.type`` and the underlying one in ``error.root_cause[0].type``, so a caller that wants
    the root cause asks for it by name rather than accepting either.
    """
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type") or "")
    return ""


def _root_cause_type(payload) -> str:
    """The FIRST root-cause type, for the exceptions the engine wraps one level deep."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        causes = error.get("root_cause") or []
        if causes and isinstance(causes[0], dict):
            return str(causes[0].get("type") or "")
    return ""


def _bulk_load(ctx, base: str, index: str, docs) -> None:
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


def _wait_index_status(ctx, base: str, index: str, want: str, timeout_s: float = 180.0) -> dict:
    """Poll _cluster/health for one index until it reaches a status; never a bare sleep.

    Bounded by the engine's own ``wait_for_status`` timeout inside a bounded outer loop, so a
    target that answers but never allocates fails rather than hangs.
    """
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        status, last = _signed_request(
            ctx, "GET", f"{base}/_cluster/health/{index}?wait_for_status={want}&timeout=30s")
        if status == 200 and last.get("timed_out") is False:
            return last
        time.sleep(2.0)
    raise AssertionError(
        f"index {index!r} did not reach status {want!r} within {timeout_s}s (last health {last!r})",
    )


def _hit_ids(result) -> list:
    return [h["_id"] for h in result.get("hits", {}).get("hits", [])]


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


# ===== end self-contained helpers =====

_SCENARIO = "reindex-into-keyword-mapping"


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """_reindex copies all six documents from a text-mapped index into a keyword-mapped one with an exact
    created count and no failures, and the same exact-value term query then matches only in the
    destination: the engine re-analyses the data under the new mapping."""
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    source, dest = "sim2real-behav-rx-src", "sim2real-behav-rx-dst"
    status, created = _signed_request(ctx, "PUT", f"{base}/{source}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"tag": {"type": "text"}, "n": {"type": "integer"}}}})
    assert status == 200, f"creating the source index returned HTTP {status!r}: {created!r}"

    # Mixed case with a space: a text field analyses this into several lowercase tokens, so the
    # unanalysed exact string can never be a term match there; a keyword field stores it whole.
    exact_tag = "Alpha Beta 3"
    docs = [(f"rx-{i}", {"tag": f"Alpha Beta {i}", "n": i}) for i in range(6)]
    _bulk_load(ctx, base, source, docs)
    status, _ = _signed_request(ctx, "POST", f"{base}/{source}/_refresh")
    assert status == 200, f"_refresh of the source index returned HTTP {status!r}"

    status, dest_created = _signed_request(ctx, "PUT", f"{base}/{dest}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"tag": {"type": "keyword"}, "n": {"type": "integer"}}}})
    assert status == 200, (
        f"creating the destination index returned HTTP {status!r}: {dest_created!r}"
    )

    status, result = _signed_request(
        ctx, "POST", f"{base}/_reindex?wait_for_completion=true&refresh=true",
        body={"source": {"index": source}, "dest": {"index": dest}})
    assert status == 200, f"_reindex returned HTTP {status!r}: {result!r}"
    assert (result.get("total"), result.get("created")) == (6, 6), (
        f"_reindex reported total/created {(result.get('total'), result.get('created'))!r}, "
        f"expected (6, 6): {result!r}"
    )
    assert result.get("failures") == [], f"_reindex reported failures: {result.get('failures')!r}"
    assert result.get("updated") == 0, (
        f"_reindex reported {result.get('updated')!r} updates into an empty destination, "
        f"expected 0 -- an update means it overwrote rather than created"
    )
    assert result.get("version_conflicts") == 0, (
        f"_reindex reported {result.get('version_conflicts')!r} version conflicts into an empty "
        f"destination, expected 0"
    )

    counts = {}
    for index in (source, dest):
        status, body = _signed_request(ctx, "GET", f"{base}/{index}/_count")
        assert status == 200, f"_count on {index!r} returned HTTP {status!r}: {body!r}"
        counts[index] = body.get("count")
    assert (counts[source], counts[dest]) == (6, 6), (
        f"document counts are {(counts[source], counts[dest])!r}, expected (6, 6) -- a reindex "
        f"must neither lose nor duplicate"
    )

    hits = {}
    for index in (source, dest):
        status, body = _signed_request(ctx, "POST", f"{base}/{index}/_search",
                                       body={"query": {"term": {"tag": exact_tag}}})
        assert status == 200, f"the term query on {index!r} returned HTTP {status!r}: {body!r}"
        hits[index] = _total(body)
    assert hits[dest] == 1, (
        f"the term query for {exact_tag!r} on the keyword-mapped destination returned "
        f"{hits[dest]!r} hits, expected 1"
    )
    assert hits[source] == 0, (
        f"the identical term query on the text-mapped source returned {hits[source]!r} hits, "
        f"expected 0 -- an analysed text field cannot match the unanalysed exact string, so a "
        f"match here means the source was never text-mapped"
    )

    status, mapping = _signed_request(ctx, "GET", f"{base}/{dest}/_mapping")
    assert status == 200, f"reading the destination _mapping returned HTTP {status!r}: {mapping!r}"
    dest_field_type = (mapping.get(dest, {}).get("mappings", {})
                       .get("properties", {}).get("tag", {}).get("type"))
    assert dest_field_type == "keyword", (
        f"the destination _mapping records field type {dest_field_type!r} for 'tag', expected "
        f"'keyword' -- the differential above is only meaningful if the mapping really changed: "
        f"{mapping!r}"
    )

    for index in (source, dest):
        status, deleted = _signed_request(ctx, "DELETE", f"{base}/{index}")
        assert status == 200, f"deleting index {index!r} returned HTTP {status!r}: {deleted!r}"
        status, body = _signed_request(ctx, "GET", f"{base}/{index}/_count")
        assert status == 404, (
            f"_count on the just-deleted index {index!r} returned HTTP {status!r}, expected 404: "
            f"{body!r}"
        )
        assert _error_type(body) == "index_not_found_exception", (
            f"_count on the just-deleted index {index!r} reported error type "
            f"{_error_type(body)!r}, expected 'index_not_found_exception': {body!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
