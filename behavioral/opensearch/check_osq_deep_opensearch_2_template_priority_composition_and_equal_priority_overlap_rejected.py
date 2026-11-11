"""osq-deep-opensearch-2-template-priority-composition-and-equal-priority-overlap-rejected."""
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

CHECK = "osq-deep-opensearch-2-template-priority-composition-and-equal-priority-overlap-rejected"
GROUP = "data-plane"
SERVICES = ["opensearch"]

# ===== self-contained helpers =====

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

# Marks a failure of the domain endpoint the target itself published, so it reads as the
# target's own fault rather than a connection problem on the caller's side.
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
        # Tagged at creation so a tag-based cleanup can find it if teardown is interrupted.
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
        f"(Processing={last.get('Processing')!r}, Endpoint={last.get('Endpoint')!r})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx wired for the target account (not boto3's ambient chain):
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
        time.sleep(2)
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


# ===== end self-contained helpers =====

_DOC = {"code": "Alpha Beta", "from_component": "Gamma Delta"}


def _put(ctx, url: str, body: dict) -> tuple:
    return _signed_request(ctx, "PUT", url, body=body)


def _mapping_properties(ctx, base: str, index: str) -> dict:
    status, body = _signed_request(ctx, "GET", f"{base}/{index}/_mapping")
    assert status == 200, f"GET {index}/_mapping returned HTTP {status!r}: {body!r}"
    return body[index]["mappings"]["properties"]


def _search(ctx, base: str, index: str, query: dict) -> tuple:
    return _signed_request(ctx, "POST", f"{base}/{index}/_search", body=query)


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """Of two composable index templates matching one auto-created index, only the higher-priority one
    (with its component template) shapes the mapping, shown by term-match and sort behaviour; a
    third template at the same priority with an overlapping pattern is refused and not stored."""
    domain = _create_min_domain(ctx)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    prefix = ctx.unique_name("sim2real-osq-tpl-").lower()
    component = f"{prefix}-ct"
    low, high, rival = f"{prefix}-low", f"{prefix}-high", f"{prefix}-rival"
    both_index = f"{prefix}-ix-hi-1"     # matches the LOW pattern and the HIGH pattern
    low_index = f"{prefix}-ix-lo-1"      # matches the LOW pattern only
    shards = {"number_of_shards": 1, "number_of_replicas": 0}

    status, body = _put(ctx, f"{base}/_component_template/{component}", {
        "template": {"mappings": {"properties": {"from_component": {"type": "keyword"}}}}})
    assert status == 200 and body.get("acknowledged") is True, (
        f"PUT _component_template returned HTTP {status!r}: {body!r}")
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/_component_template/{component}"))

    status, body = _put(ctx, f"{base}/_index_template/{low}", {
        "index_patterns": [f"{prefix}-ix-*"], "priority": 100,
        "template": {"settings": shards, "mappings": {"properties": {
            "code": {"type": "text"}, "low_only": {"type": "integer"}}}}})
    assert status == 200 and body.get("acknowledged") is True, (
        f"PUT low-priority _index_template returned HTTP {status!r}: {body!r}")
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/_index_template/{low}"))

    status, body = _put(ctx, f"{base}/_index_template/{high}", {
        "index_patterns": [f"{prefix}-ix-hi-*"], "priority": 200, "composed_of": [component],
        "template": {"settings": shards, "mappings": {"properties": {"code": {"type": "keyword"}}}}})
    assert status == 200 and body.get("acknowledged") is True, (
        f"PUT high-priority _index_template returned HTTP {status!r}: {body!r}")
    # Registered before the component's delete runs (LIFO): a template that is composed_of a
    # component must go first, or the component delete is refused.
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/_index_template/{high}"))

    # Both indices are created IMPLICITLY by the document write -- the template is applied by the
    # target at auto-create time, which is the behaviour under test.
    for index in (both_index, low_index):
        ctx.on_cleanup(lambda index=index: _signed_request(ctx, "DELETE", f"{base}/{index}"))
        status, body = _put(ctx, f"{base}/{index}/_doc/d1?refresh=true", _DOC)
        assert status == 201 and body.get("result") == "created", (
            f"indexing into the not-yet-existing index {index!r} returned HTTP {status!r}, "
            f"expected 201 created via auto-create: {body!r}")

    # PRECEDENCE in the effective mapping.
    won = _mapping_properties(ctx, base, both_index)
    assert won.get("code") == {"type": "keyword"}, (
        f"{both_index!r} matches both templates; the priority-200 one maps 'code' as keyword, the "
        f"priority-100 one as text. Effective mapping for 'code' is {won.get('code')!r}: {won!r}")
    assert "low_only" not in won, (
        f"the losing priority-100 template's field 'low_only' leaked into {both_index!r}: only ONE "
        f"index template applies, templates are not merged with each other: {won!r}")
    # COMPOSITION: the component template's field merged in with ITS type, not a dynamic mapping
    # (which would have been text + a .keyword sub-field, as the control index below shows).
    assert won.get("from_component") == {"type": "keyword"}, (
        f"the component template maps 'from_component' as keyword; {both_index!r} reports "
        f"{won.get('from_component')!r}, so composed_of was not merged: {won!r}")
    assert set(won) == {"code", "from_component"}, (
        f"effective mapping fields are {sorted(won)!r}, expected exactly ['code', 'from_component']")

    # CONTROL: an index only the loser matches gets the loser's mapping and nothing from the
    # component template (its 'from_component' is DYNAMIC text with a keyword sub-field).
    lost = _mapping_properties(ctx, base, low_index)
    assert lost.get("code") == {"type": "text"}, (
        f"{low_index!r} matches only the priority-100 template; 'code' is {lost.get('code')!r}")
    assert lost.get("low_only") == {"type": "integer"}, (
        f"{low_index!r} should carry the priority-100 template's 'low_only' field: {lost!r}")
    assert lost.get("from_component", {}).get("type") == "text", (
        f"{low_index!r} has no component template, so 'from_component' must be dynamically mapped "
        f"text, got {lost.get('from_component')!r}")

    # CONSEQUENCE of the winner: an exact term on the keyword field hits; on the text field the same
    # term misses, because 'Alpha Beta' was analysed into ['alpha', 'beta'].
    term = {"query": {"term": {"code": "Alpha Beta"}}}
    status, hit = _search(ctx, base, both_index, term)
    assert status == 200 and _hit_ids(hit) == ["d1"], (
        f"term 'Alpha Beta' on keyword 'code' in {both_index!r} returned HTTP {status!r} with ids "
        f"{_hit_ids(hit) if status == 200 else hit!r}, expected ['d1']")
    status, miss = _search(ctx, base, low_index, term)
    assert status == 200 and _total(miss) == 0, (
        f"term 'Alpha Beta' on text 'code' in {low_index!r} must match nothing (the value is "
        f"analysed into lowercase tokens); got HTTP {status!r}: {miss!r}")
    status, comp = _search(ctx, base, both_index, {"query": {"term": {"from_component": "Gamma Delta"}}})
    assert status == 200 and _hit_ids(comp) == ["d1"], (
        f"exact term on the component-mapped keyword 'from_component' returned HTTP {status!r}: "
        f"{comp!r}")

    status, sorted_ok = _search(ctx, base, both_index, {"sort": [{"code": "asc"}]})
    assert status == 200 and sorted_ok["hits"]["hits"][0].get("sort") == ["Alpha Beta"], (
        f"sorting on keyword 'code' returned HTTP {status!r}: {sorted_ok!r}")
    status, refused = _search(ctx, base, low_index, {"sort": [{"code": "asc"}]})
    assert status == 400, f"sorting on text 'code' must be refused with 400, got {status!r}: {refused!r}"
    root = refused.get("error", {}).get("root_cause", [])
    assert [c.get("type") for c in root] == ["illegal_argument_exception"] and \
        "Text fields are not optimised" in root[0].get("reason", ""), (
            f"sort on a text field must fail with the fielddata illegal_argument_exception, got "
            f"{root!r}")

    # THE ONE BROKEN THING: a rival template at the winner's priority with an overlapping pattern.
    status, rejected = _put(ctx, f"{base}/_index_template/{rival}", {
        "index_patterns": [f"{prefix}-ix-hi-x*"], "priority": 200,
        "template": {"mappings": {"properties": {"code": {"type": "text"}}}}})
    if status == 200:
        ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/_index_template/{rival}"))
    assert status == 400, (
        f"a priority-200 template overlapping the existing priority-200 {high!r} must be refused "
        f"with HTTP 400, got {status!r}: {rejected!r}")
    assert _error_type(rejected) == "illegal_argument_exception", (
        f"expected illegal_argument_exception, got {_error_type(rejected)!r}: {rejected!r}")
    expected_reason = (
        f"index template [{rival}] has index patterns [{prefix}-ix-hi-x*] matching patterns from "
        f"existing templates [{high}] with patterns ({high} => [{prefix}-ix-hi-*]) that have the "
        f"same priority [200], multiple index templates may not match during index creation, "
        f"please use a different priority")
    assert rejected["error"].get("reason") == expected_reason, (
        f"refusal reason was {rejected['error'].get('reason')!r}, expected {expected_reason!r}")
    # EFFECT ABSENT: the refused template was not stored.
    status, absent = _signed_request(ctx, "GET", f"{base}/_index_template/{rival}")
    assert status == 404 and _error_type(absent) == "resource_not_found_exception", (
        f"the refused template must not exist; GET returned HTTP {status!r}: {absent!r}")
    # POSITIVE CONTROL: the same priority is legal for a pattern that overlaps nothing.
    status, ok = _put(ctx, f"{base}/_index_template/{rival}", {
        "index_patterns": [f"{prefix}-elsewhere-*"], "priority": 200})
    if status == 200:
        ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/_index_template/{rival}"))
    assert status == 200 and ok.get("acknowledged") is True, (
        f"priority 200 on a NON-overlapping pattern must be accepted, got HTTP {status!r}: {ok!r}")
    # And the winner still governs: an index created after the refusal still gets keyword 'code'.
    late = f"{prefix}-ix-hi-2"
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/{late}"))
    status, body = _put(ctx, f"{base}/{late}/_doc/d2?refresh=true", _DOC)
    assert status == 201, f"auto-creating {late!r} returned HTTP {status!r}: {body!r}"
    late_props = _mapping_properties(ctx, base, late)
    assert late_props.get("code") == {"type": "keyword"}, (
        f"after the refused PUT, {late!r} reports 'code' {late_props.get('code')!r}, expected the "
        f"winning template's keyword")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
