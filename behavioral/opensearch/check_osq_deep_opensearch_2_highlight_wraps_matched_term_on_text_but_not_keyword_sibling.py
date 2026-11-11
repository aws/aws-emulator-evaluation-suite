"""osq-deep-opensearch-2-highlight-wraps-matched-term-on-text-but-not-keyword-sibling."""
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

CHECK = "osq-deep-opensearch-2-highlight-wraps-matched-term-on-text-but-not-keyword-sibling"
GROUP = "data-plane"
SERVICES = ["opensearch"]


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

# Marks a domain endpoint the target published and then failed to answer on.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _never_ready(msg: str) -> AssertionError:
    """The error for a resource that never converged; returned to keep ``from exc`` chaining."""
    return AssertionError(msg)


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created / already deleted."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _account_access_policy(ctx, domain_name: str) -> str:
    """Resource policy letting this account's principals use the data plane (account from STS)."""
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
        # Tagged at creation so a tag-scanning cleanup can find it if teardown is interrupted.
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


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1500.0) -> str:
    """Poll to Processing=False and a published Endpoint."""
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
        f"(Processing={last.get('Processing')!r}, Endpoint={last.get('Endpoint')!r})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with ctx's credentials, not boto3's ambient chain: the wrong principal gets a 403.
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
    """Poll a cheap signed GET until it stops 403ing: a published Endpoint does not mean the
    data-plane authorizer has the access policy yet."""
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

    A 2xx body has no 'error' and yields the literal '<no error>'."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type"))
    return "<no error>"


def _total(result) -> int:
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


def _hit_ids(result) -> list:
    return [h["_id"] for h in result["hits"]["hits"]]


_SCENARIO_WORDS = ("the quick brown", "jumps over the lazy dog")


def _search(ctx, base: str, index: str, query: dict) -> dict:
    status, body = _signed_request(ctx, "POST", f"{base}/{index}/_search", body=query)
    assert status == 200, f"_search {query!r} on {index!r} returned HTTP {status!r}: {body!r}"
    return body


def _only_hit(result: dict, what: str) -> dict:
    hits = result["hits"]["hits"]
    assert _total(result) == 1 and [h["_id"] for h in hits] == ["h1"], (
        f"{what}: expected exactly the one indexed document 'h1', got total {_total(result)!r} "
        f"ids {[h['_id'] for h in hits]!r}")
    return hits[0]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Highlighting follows the analysed tokens: a match on a `text` field wraps exactly the matched
    token in `<em>`, while its `.keyword` sibling returns no fragment for that query (even with
    require_field_match false) and, matched by its exact value, is highlighted as one unit."""
    import uuid

    domain = _create_min_domain(ctx)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = ctx.unique_name("sim2real-osq-hl-").lower()
    status, body = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"dynamic": "strict", "properties": {
            "body": {"type": "text", "fields": {"keyword": {"type": "keyword"}}}}}})
    assert status == 200 and body.get("acknowledged") is True, (
        f"creating index {index!r} returned HTTP {status!r}: {body!r}")
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/{index}"))

    # Freshly minted, lowercase-alphanumeric token: the standard analyzer keeps it as one token, and
    # no other document anywhere can contain it.
    token = "zq" + uuid.uuid4().hex[:12]
    text = f"{_SCENARIO_WORDS[0]} {token} {_SCENARIO_WORDS[1]}"
    status, body = _signed_request(ctx, "PUT", f"{base}/{index}/_doc/h1?refresh=true",
                                   body={"body": text})
    assert status == 201 and body.get("result") == "created", (
        f"indexing the document returned HTTP {status!r}: {body!r}")

    # TEXT field: the matched token, and only it, is wrapped.
    hit = _only_hit(_search(ctx, base, index, {
        "query": {"match": {"body": token}},
        "highlight": {"fields": {"body": {}, "body.keyword": {}}}}), "match on text 'body'")
    highlight = hit.get("highlight")
    assert isinstance(highlight, dict), f"a match on 'body' returned no highlight section: {hit!r}"
    expected_fragment = f"{_SCENARIO_WORDS[0]} <em>{token}</em> {_SCENARIO_WORDS[1]}"
    assert highlight.get("body") == [expected_fragment], (
        f"text-field highlight was {highlight.get('body')!r}, expected [{expected_fragment!r}] -- "
        f"exactly the minted token wrapped, nothing else")
    # KEYWORD sibling, same query, same request: no fragment at all.
    assert set(highlight) == {"body"}, (
        f"the same token query must yield NO fragment for the un-analysed 'body.keyword' sibling; "
        f"highlight keys were {sorted(highlight)!r}: {highlight!r}")

    # Even with require_field_match disabled the keyword sibling has nothing to mark: the token is
    # not a term of the keyword field.
    hit = _only_hit(_search(ctx, base, index, {
        "query": {"match": {"body": token}},
        "highlight": {"require_field_match": False, "fields": {"body.keyword": {}}}}),
        "match on text 'body', highlighting only 'body.keyword'")
    assert "highlight" not in hit, (
        f"with require_field_match=false the keyword sibling still has no term equal to {token!r}, "
        f"so no fragment may be returned; got {hit.get('highlight')!r}")

    # The token cannot match the keyword field at all -- the reason the fragment is absent.
    nothing = _search(ctx, base, index, {"query": {"match": {"body.keyword": token}}})
    assert _total(nothing) == 0, (
        f"the token {token!r} must not match the un-analysed keyword value; got {nothing['hits']!r}")

    # Positive control on the keyword field: a keyword field does highlight, but only an exact
    # whole-value match, and as one <em> pair around the entire value.
    hit = _only_hit(_search(ctx, base, index, {
        "query": {"term": {"body.keyword": text}},
        "highlight": {"fields": {"body.keyword": {}}}}), "exact term on 'body.keyword'")
    assert hit.get("highlight") == {"body.keyword": [f"<em>{text}</em>"]}, (
        f"exact-value term on the keyword field must highlight the WHOLE value as one unit, "
        f"expected {{'body.keyword': [{f'<em>{text}</em>'!r}]}}, got {hit.get('highlight')!r}")
    assert hit["_source"] == {"body": text}, f"_source changed: {hit['_source']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
