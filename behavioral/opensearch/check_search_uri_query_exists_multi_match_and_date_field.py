"""search-uri-query-exists-multi-match-and-date-field."""

from __future__ import annotations

import http.client
import json
import random
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-uri-query-exists-multi-match-and-date-field"
GROUP = "data-plane"
SERVICES = ["opensearch"]

# ===== shared domain helpers =====

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


def _capped_s(ctx, timeout_s: float) -> float:
    """timeout_s, capped by the run's time left less a few seconds for the check's own message."""
    left = ctx.time_left()
    return timeout_s if left is None else max(0.0, min(timeout_s, left - 5.0))


def _delete_domain(osc, domain_name: str) -> None:
    """Teardown: a domain that was never created or is already gone is done; other errors raise."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _account_access_policy(ctx, domain_name: str) -> str:
    """Resource-based policy letting this account's principals use the data plane."""
    account_id = ctx.account
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "es:*",
                    "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}/*",
                }
            ],
        }
    )


def _create_min_domain(ctx, *, scenario: str) -> str:
    """Create the cheapest legal domain, its teardown registered before the create call."""
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    ctx.on_cleanup(lambda: _delete_domain(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        AccessPolicies=_account_access_policy(ctx, domain_name),
        # Tagged at creation so tag-based discovery finds it.
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    # CreateDomain is rate limited per account: back off on throttling.
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
    """Wait for Processing=False and a published Endpoint, capped by the time left."""
    osc = ctx.client("opensearch")
    budget = _capped_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    while True:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"domain {domain_name} did not publish a searchable endpoint within {budget:.0f}s "
                f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})"
            )
        time.sleep(15)


def _ssl_context(verify):
    """The TLS context for ``ctx.http_verify``: a CA bundle path, True, or False if exempt."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _signed_request(ctx, method, url, *, body=None):
    """SigV4-signed ('es') request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx wired for the target account, so the domain's account-scoped
    policy admits it; sends with stdlib urllib.
    """
    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    aws_req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)
    req = urllib.request.Request(url, data=data, method=method, headers=dict(aws_req.headers))
    tls = _ssl_context(ctx.http_verify)
    try:
        with urllib.request.urlopen(req, timeout=120, context=tls) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(text)
        except ValueError:
            return exc.code, {"raw": text}
    except (OSError, http.client.HTTPException) as exc:
        # The endpoint was published by the target, so not answering on it is the target's failure.
        raise AssertionError(
            f"signed {method} to the published domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 300.0) -> None:
    """Poll a cheap signed GET until the data plane stops answering 403, capped by the time left.

    A published Endpoint does not mean the data-plane authorizer has the access policy yet.
    """
    budget = _capped_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    while True:
        status, _ = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"domain data plane still answered 403 after {budget:.0f}s")
        time.sleep(5)


def _hit_ids(result) -> set:
    return {h["_id"] for h in result.get("hits", {}).get("hits", [])}


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


# ===== end shared domain helpers =====

_INDEX = "sim2real-behav-query-kinds"
#: d2 holds, as epoch milliseconds, the last second before the day d0 is published on.
_DOCS = {
    "d0": {"title": "red apple", "body": "fresh fruit", "published": "2026-01-01", "rating": 5},
    "d1": {"title": "green pear", "body": "red skin", "published": "2026-02-15"},
    "d2": {"title": "blue sky", "body": "clear day", "published": 1767225599000, "rating": 3},
}


def _search(ctx, base: str, *, query=None, q=None):
    """Run one search (a request-body query, or a URI ``q``) and return its result."""
    if q is not None:
        url = f"{base}/{_INDEX}/_search?q={urllib.parse.quote(q, safe='')}"
        status, result = _signed_request(ctx, "GET", url)
    else:
        url = f"{base}/{_INDEX}/_search"
        status, result = _signed_request(ctx, "POST", url, body={"query": query})
    assert status == 200, f"search {q or query} failed with HTTP {status}: {result}"
    return result


def _assert_hits(result, want: set, desc: str) -> None:
    assert _hit_ids(result) == want, (
        f"{desc} must match {sorted(want)}, got {sorted(_hit_ids(result))}"
    )
    assert _total(result) == len(want), (
        f"{desc} hits.total must be {len(want)}, got {_total(result)}"
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A date field takes a yyyy-MM-dd string and epoch millis; URI q, exists and multi_match match.

    URI q matches a field or all fields, exists keeps only documents with the field, multi_match
    searches only the fields named, and a date range compares instants.
    """
    domain = _create_min_domain(ctx, scenario=CHECK)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    status, created = _signed_request(
        ctx,
        "PUT",
        f"{base}/{_INDEX}",
        body={
            "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
            "mappings": {
                "properties": {
                    "title": {"type": "text"},
                    "body": {"type": "text"},
                    "published": {"type": "date"},
                    "rating": {"type": "integer"},
                }
            },
        },
    )
    assert status == 200, f"creating index failed with HTTP {status}: {created}"

    for doc_id, doc in _DOCS.items():
        url = f"{base}/{_INDEX}/_doc/{doc_id}"
        status, indexed = _signed_request(ctx, "PUT", url, body=doc)
        assert status == 201 and indexed.get("result") == "created", (
            f"indexing {doc_id} with published={doc['published']!r} must be created (HTTP 201), "
            f"got HTTP {status}: {indexed}"
        )
    status, refreshed = _signed_request(ctx, "POST", f"{base}/{_INDEX}/_refresh")
    assert status == 200, f"_refresh failed with HTTP {status}: {refreshed}"

    status, got = _signed_request(ctx, "GET", f"{base}/{_INDEX}/_doc/d0")
    assert status == 200, f"GET d0 failed with HTTP {status}: {got}"
    assert got.get("_source") == _DOCS["d0"], f"_source must round-trip verbatim, got {got}"

    _assert_hits(_search(ctx, base, q="title:apple"), {"d0"}, "URI q=title:apple")
    _assert_hits(_search(ctx, base, q="red"), {"d0", "d1"}, "URI q=red over all fields")
    _assert_hits(
        _search(ctx, base, query={"exists": {"field": "rating"}}), {"d0", "d2"}, "exists rating"
    )
    _assert_hits(
        _search(ctx, base, query={"multi_match": {"query": "red", "fields": ["title", "body"]}}),
        {"d0", "d1"},
        "multi_match red over title and body",
    )
    _assert_hits(
        _search(ctx, base, query={"multi_match": {"query": "red", "fields": ["title"]}}),
        {"d0"},
        "multi_match red over title only",
    )
    _assert_hits(
        _search(ctx, base, query={"range": {"published": {"gte": "2026-01-01"}}}),
        {"d0", "d1"},
        "range published >= 2026-01-01",
    )
    _assert_hits(_search(ctx, base, q="published:2026-01-01"), {"d0"}, "URI q=published:2026-01-01")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
