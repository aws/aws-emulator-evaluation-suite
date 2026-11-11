"""os-index-document-search-roundtrip."""
from __future__ import annotations

import random
import ssl
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "os-index-document-search-roundtrip"
GROUP = 'data-plane'
SERVICES = ['opensearch']

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
}

MIN_EBS_OPTIONS = {
    "EBSEnabled": True,
    "VolumeType": "gp3",
    "VolumeSize": 10,
}

ENGINE_VERSION = "OpenSearch_2.11"

# An endpoint data-plane FAIL marker: a target that never answers the signed data-plane request
# at all is scored a real fidelity failure, ahead of any generic connection-error classification.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

def _signed_json_request(ctx, method: str, url: str, body=None):
    """Send a SigV4-signed ('es') HTTPS request to a domain endpoint.

    Signs with botocore (always available) and sends with stdlib urllib so the
    check needs no third-party HTTP client. Returns (status_code, parsed_json).
    """
    import json as _json
    import urllib.error
    import urllib.request

    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    # Sign with the SAME credentials ctx wired for this check's account — NOT boto3's ambient
    # chain. Signing with the ambient account makes the data-plane request come from the wrong
    # principal, which the domain's account-scoped ":root" access policy 403s.
    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()

    data = _json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    aws_req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)

    req = urllib.request.Request(url, data=data, method=method, headers=dict(aws_req.headers))
    # Trust exactly what ctx.http_verify names: False -> unverified, a path -> that CA bundle.
    verify = ctx.http_verify
    ssl_ctx = (ssl._create_unverified_context() if verify is False
               else ssl.create_default_context(cafile=verify if isinstance(verify, str) else None))
    try:
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
            raw = resp.read().decode()
            return resp.status, (_json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            parsed = _json.loads(raw)
        except ValueError:
            parsed = {"raw": raw}
        return exc.code, parsed
    except (urllib.error.URLError, OSError) as exc:
        # An HTTP status (above) is data the caller asserts on; a transport failure is not, and
        # urllib reports it in wording that reads as a local network problem ("Connection refused",
        # "timed out"), which leaves the pass+fail denominator. The endpoint here was published by
        # the target itself, so failing to answer on it is the target's fidelity failure.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

def _searchable_domain_access_policy(ctx, domain_name: str) -> str:
    """An access policy allowing the caller's own account to use the data plane."""
    import json as _json

    account_id = ctx.account
    arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}"
    return _json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"{arn}/*",
        }],
    })

def _wait_domain_searchable(ctx, domain_name: str, timeout_s: float = 1800):
    """Poll until the domain is done Processing AND has published an Endpoint.

    Raises AssertionError if the domain never becomes searchable within the budget —
    this check never skips (see the two raise sites below for how real AWS vs. an
    emulator target are told apart in the message, not in whether it fails).
    """
    osc = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            status = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            # Concurrent domain polls in one account hit DescribeDomain's rate limit: poll again.
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(2)
            continue
        last = status
        if status.get("Processing") is False and status.get("Endpoint"):
            return status["Endpoint"]
        time.sleep(2)
    detail = (
        f"domain {domain_name} never became searchable within {timeout_s}s "
        f"(last Processing={last.get('Processing') if last else '?'}, "
        f"Endpoint={last.get('Endpoint') if last else '?'})"
    )
    raise AssertionError(detail)

@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A document indexed into a live domain is found by search and by id with its source; once deleted it is gone
    by id and from search, and once its index is deleted, GET and _close on it fail 404 index_not_found_exception
    and _cat/indices omits it.
    """
    osc = ctx.client("opensearch")

    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    for _attempt in range(12):
        try:
            osc.create_domain(
                DomainName=domain_name,
                EngineVersion=ENGINE_VERSION,
                ClusterConfig=dict(MIN_CLUSTER_CONFIG),
                EBSOptions=dict(MIN_EBS_OPTIONS),
                AccessPolicies=_searchable_domain_access_policy(ctx, domain_name),
                # Untagged, this domain would be invisible to a tag-based leak scan and so
                # unrecoverable if teardown were ever interrupted.
                TagList=[{"Key": "sim2real:managed", "Value": "true"}],
            )
            break
        except ClientError as _e:
            if _e.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + _attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError("still throttled after 12 attempts")
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain_name))

    endpoint = _wait_domain_searchable(ctx, domain_name)
    base = ctx.endpoint_url(endpoint)
    # Control-plane ACTIVE + a published Endpoint does NOT mean the data-plane authorizer has the
    # access policy yet; a signed request can 403 for a while after the domain goes searchable.
    # Poll a lightweight signed GET until it stops returning 403 before exercising index/search.
    _dp_deadline = time.monotonic() + 300
    while time.monotonic() < _dp_deadline:
        _st, _ = _signed_json_request(ctx, "GET", f"{base}/")
        if _st != 403:
            break
        time.sleep(2)
    index = ctx.unique_name("sim2real-behav-idx-")
    doc = {"title": "sim2real", "marker": domain_name}

    # PUT a document into the index (auto-creates the index).
    status, _ = _signed_json_request(ctx, "PUT", f"{base}/{index}/_doc/1", doc)
    assert status in (200, 201), f"indexing document failed with HTTP {status}"

    # Refresh so the document is immediately visible to search.
    status, _ = _signed_json_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"index refresh failed with HTTP {status}"

    # Search it back and assert the document is returned.
    query = {"query": {"match": {"title": "sim2real"}}}
    status, result = _signed_json_request(ctx, "POST", f"{base}/{index}/_search", query)
    assert status == 200, f"_search failed with HTTP {status}: {result}"
    total = result.get("hits", {}).get("total", {})
    total_value = total.get("value") if isinstance(total, dict) else total
    assert total_value and total_value >= 1, f"search returned no hits: {result.get('hits')}"
    hits = result["hits"]["hits"]
    assert any(hit.get("_source", {}).get("marker") == domain_name for hit in hits), (
        f"indexed document not found in search hits: {hits}"
    )

    # Independent read by id: the document is stored with its source.
    status, got = _signed_json_request(ctx, "GET", f"{base}/{index}/_doc/1")
    assert status == 200 and got.get("found") is True, (
        f"GET _doc/1 expected 200 found:true, got HTTP {status}: {got}"
    )
    assert got.get("_source") == doc, f"GET _doc/1 _source expected {doc}, got {got.get('_source')}"

    # Delete the document, then prove it is gone by id and from search.
    status, deleted = _signed_json_request(ctx, "DELETE", f"{base}/{index}/_doc/1")
    assert status == 200 and deleted.get("result") == "deleted", (
        f"DELETE _doc/1 expected 200 result 'deleted', got HTTP {status}: {deleted}"
    )
    status, got = _signed_json_request(ctx, "GET", f"{base}/{index}/_doc/1")
    assert status == 404 and got.get("found") is False, (
        f"GET deleted _doc/1 expected 404 found:false, got HTTP {status}: {got}"
    )
    status, _ = _signed_json_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"index refresh after delete failed with HTTP {status}"
    status, result = _signed_json_request(ctx, "POST", f"{base}/{index}/_search", query)
    assert status == 200, f"_search after delete failed with HTTP {status}: {result}"
    total = result["hits"]["total"]
    total_value = total["value"] if isinstance(total, dict) else total
    assert total_value == 0, f"search after delete expected 0 hits, got {result['hits']}"

    # Delete the index; the domain itself is torn down by cleanup.
    status, body = _signed_json_request(ctx, "DELETE", f"{base}/{index}")
    assert status == 200, f"DELETE index expected HTTP 200, got {status}: {body}"

    # Gone 1: a read by name answers 404 index_not_found_exception whose structured index field
    # is the index (the free-text reason is not graded).
    status, body = _signed_json_request(ctx, "GET", f"{base}/{index}")
    err = body.get("error") if isinstance(body, dict) else None
    assert status == 404 and isinstance(err, dict) and err.get("type") == "index_not_found_exception", (
        f"GET deleted index expected 404 index_not_found_exception, got HTTP {status}: {body}"
    )
    assert err.get("index") == index, (
        f"index_not_found_exception should carry index={index!r}, got {err}"
    )
    # Gone 2: the index listing has no row for it.
    status, rows = _signed_json_request(ctx, "GET", f"{base}/_cat/indices?format=json")
    assert status == 200 and isinstance(rows, list), (
        f"_cat/indices expected 200 and a JSON list, got HTTP {status}: {rows}"
    )
    assert not [r for r in rows if r.get("index") == index], (
        f"_cat/indices still lists the deleted index: {[r for r in rows if r.get('index') == index]}"
    )
    # Gone 3: a mutation on the dead index is refused not-found.
    status, body = _signed_json_request(ctx, "POST", f"{base}/{index}/_close")
    err = body.get("error") if isinstance(body, dict) else None
    assert status == 404 and isinstance(err, dict) and err.get("type") == "index_not_found_exception", (
        f"POST _close on deleted index expected 404 index_not_found_exception, got HTTP {status}: {body}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
