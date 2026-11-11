"""bulk-index-partial-failure-item-errors-rejected."""
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

CHECK = "bulk-index-partial-failure-item-errors-rejected"
GROUP = 'data-plane'
SERVICES = ['opensearch']

# ===== shared domain helpers =====

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


# Prefix of the failure raised when a domain the target accepted never reaches the awaited state,
# so that outcome reads as the target's failure rather than as a local network problem.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The "resource did not converge" verdict, the same on every target.

    A state the target ACCEPTED and then never reached within the budget carries STATE_MARKER, so
    it reads as the target's answer rather than as a local environment problem. The wait that
    raises it polls the same terminal condition with the same budget on every target.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


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
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: jitter, then backoff on throttling.
    for attempt in range(12):
        time.sleep(random.uniform(0, 20.0) if attempt == 0 else 6.0 * attempt + random.uniform(0, 6.0))
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1800.0) -> str:
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
    raise _never_ready(
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
        time.sleep(2)
    raise AssertionError(f"domain data plane still 403 after {timeout_s}s (last status {status})")


def _ndjson(lines) -> str:
    """_bulk wants newline-delimited JSON with a MANDATORY trailing newline."""
    return "".join(json.dumps(line) + "\n" for line in lines)


# ===== end shared domain helpers =====

_PARSE_ERROR_TYPES = ("mapper_parsing_exception", "document_parsing_exception")


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """REAL BACKEND: a _bulk request that mixes valid and invalid documents returns HTTP 200
    with errors=true and a PER-ITEM error, indexes only the valid documents, and leaves the
    invalid one absent.
    """
    domain = _create_min_domain(ctx)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = "sim2real-behav-bulk"
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"sku": {"type": "keyword"}, "count": {"type": "integer"}}},
    })
    assert status in (200, 201), f"creating index failed with HTTP {status}: {created}"
    assert created.get("acknowledged") is True, f"index creation not acknowledged: {created}"

    # Three well-typed documents plus one whose "count" cannot be coerced to an integer.
    payload = _ndjson([
        {"index": {"_index": index, "_id": "ok-1"}}, {"sku": "a", "count": 1},
        {"index": {"_index": index, "_id": "ok-2"}}, {"sku": "b", "count": 2},
        {"index": {"_index": index, "_id": "bad-1"}}, {"sku": "c", "count": "not-a-number"},
        {"index": {"_index": index, "_id": "ok-3"}}, {"sku": "d", "count": 4},
    ])
    status, bulk = _signed_request(
        ctx, "POST", f"{base}/_bulk", raw=payload, content_type="application/x-ndjson"
    )
    assert status == 200, (
        f"_bulk with a partial failure must still return HTTP 200, got {status}: {bulk}"
    )
    assert bulk.get("errors") is True, f"_bulk must report errors=true, got {bulk.get('errors')}"
    items = bulk.get("items", [])
    assert len(items) == 4, f"expected 4 _bulk items, got {len(items)}: {items}"

    by_id = {item["index"]["_id"]: item["index"] for item in items}
    for ok_id in ("ok-1", "ok-2", "ok-3"):
        entry = by_id.get(ok_id, {})
        assert entry.get("status") == 201, (
            f"valid bulk item {ok_id} should have status 201, got {entry.get('status')}: {entry}"
        )
        assert "error" not in entry, f"valid bulk item {ok_id} carries an error: {entry}"

    bad = by_id.get("bad-1", {})
    assert bad.get("status") == 400, (
        f"invalid bulk item must carry status 400, got {bad.get('status')}: {bad}"
    )
    bad_error = bad.get("error", {})
    assert bad_error.get("type") in _PARSE_ERROR_TYPES, (
        f"invalid bulk item must fail with one of {_PARSE_ERROR_TYPES}, "
        f"got {bad_error.get('type')!r}: {bad_error}"
    )
    assert "count" in str(bad_error.get("reason", "")), (
        f"per-item error must name the offending field 'count', got {bad_error.get('reason')!r}"
    )

    status, refreshed = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"_refresh failed with HTTP {status}: {refreshed}"

    # Effect absent: exactly the three valid documents landed.
    status, count = _signed_request(ctx, "GET", f"{base}/{index}/_count")
    assert status == 200, f"_count failed with HTTP {status}: {count}"
    assert count.get("count") == 3, (
        f"only the 3 valid documents should be indexed, _count says {count.get('count')}"
    )
    status, missing = _signed_request(ctx, "GET", f"{base}/{index}/_doc/bad-1")
    assert status == 404, f"rejected document must not exist, GET returned {status}: {missing}"
    assert missing.get("found") is False, f"rejected document reported as found: {missing}"

    # Control: the valid documents are readable and correctly typed.
    status, present = _signed_request(ctx, "GET", f"{base}/{index}/_doc/ok-3")
    assert status == 200, f"valid document unreadable, GET returned {status}: {present}"
    assert present.get("_source", {}).get("count") == 4, (
        f"valid document body corrupted: {present.get('_source')}"
    )

    # Control: an all-valid bulk must report errors=false -- the flag is computed, not hardwired.
    clean = _ndjson([
        {"index": {"_index": index, "_id": "ok-4"}}, {"sku": "e", "count": 5},
        {"index": {"_index": index, "_id": "ok-5"}}, {"sku": "f", "count": 6},
    ])
    status, clean_bulk = _signed_request(
        ctx, "POST", f"{base}/_bulk", raw=clean, content_type="application/x-ndjson"
    )
    assert status == 200, f"all-valid _bulk failed with HTTP {status}: {clean_bulk}"
    assert clean_bulk.get("errors") is False, (
        f"all-valid _bulk must report errors=false, got {clean_bulk.get('errors')}: {clean_bulk}"
    )

    # Independent terminal read: the two new documents actually landed, not just a computed flag.
    status, refreshed2 = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"_refresh after clean bulk failed with HTTP {status}: {refreshed2}"
    status, count2 = _signed_request(ctx, "GET", f"{base}/{index}/_count")
    assert status == 200, f"_count after clean bulk failed with HTTP {status}: {count2}"
    assert count2.get("count") == 5, (
        f"after the all-valid bulk, 5 documents (3 earlier + 2 new) should be indexed, "
        f"_count says {count2.get('count')}"
    )

    status, deleted = _signed_request(ctx, "DELETE", f"{base}/{index}")
    assert status == 200, f"deleting index failed with HTTP {status}: {deleted}"
    assert deleted.get("acknowledged") is True, f"index delete not acknowledged: {deleted}"
    status, gone = _signed_request(ctx, "GET", f"{base}/{index}/_count")
    assert status == 404, f"deleted index must not be readable, GET _count returned {status}: {gone}"
    gone_error = gone.get("error", {})
    gone_type = gone_error.get("type") if isinstance(gone_error, dict) else None
    assert gone_type == "index_not_found_exception", (
        f"deleted index must fail with index_not_found_exception, got {gone_type!r}: {gone}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
