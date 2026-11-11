"""closed-index-search-rejected-and-reopen-restores-documents."""
from __future__ import annotations

import http.client
import json
import random
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "closed-index-search-rejected-and-reopen-restores-documents"
GROUP = 'data-plane'
SERVICES = ['opensearch']

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

# Prefix of the failure raised when a domain endpoint the target published does not answer, so
# that outcome reads as the target's failure rather than as a local network problem.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
# The CONTROL-PLANE convergence counterpart, for a domain that was accepted and never converged.
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
    account_id = ctx.account
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
        # Tagged at creation so tag-based cleanup can find leaked domains: it discovers what to
        # delete through the Resource Groups Tagging API and sees nothing else.
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: back off on throttling.
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

    The budget is sized so the whole check fits an 1800 s per-check timeout; provisioning this
    topology takes roughly 11-14 min.
    """
    osc = ctx.client("opensearch")
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2)
    raise _never_ready(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _ssl_context(verify):
    """The TLS context for ``ctx.http_verify``: a CA bundle path, True, or False on a target it exempts."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


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
    except (OSError, http.client.HTTPException) as exc:  # the endpoint did not answer at all
        # An HTTP status (above) is data the caller asserts on; a transport failure is not, and
        # urllib reports it in wording that reads as a local network problem ("Connection refused",
        # "timed out"), which leaves the pass+fail denominator. The endpoint here was published by
        # the target itself, so failing to answer on it is the target's fidelity failure.
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
    raise _never_ready(
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
    raise _never_ready(
        f"index {index!r} did not reach status {want!r} within {timeout_s}s (last health {last!r})",
    )


def _error_names_index(payload, index: str) -> bool:
    """True when the engine error names ``index`` in its ``index`` field, reason or root cause."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if not isinstance(error, dict):
        return False
    causes = error.get("root_cause") or [{}]
    first = causes[0] if isinstance(causes[0], dict) else {}
    return index in (error.get("index"), first.get("index")) or index in str(error.get("reason", ""))


def _hit_ids(result) -> list:
    return [h["_id"] for h in result.get("hits", {}).get("hits", [])]


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


# ===== end shared domain helpers =====

_SCENARIO = "closed-index-search-rejected"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Closing an index refuses the identical search with index_closed_exception while _cat/indices
    lists it as 'close', and reopening it returns the same four document ids: close is not a delete.
    """
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = "sim2real-behav-closed"
    # One primary, no replicas: a single shard keeps close/open allocation deterministic.
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"n": {"type": "integer"}}}})
    assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"

    doc_ids = [f"closed-{i}" for i in range(4)]
    _bulk_load(ctx, base, index, [(i, {"n": n}) for n, i in enumerate(doc_ids)])
    status, _ = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"_refresh before the close returned HTTP {status!r}"

    query = {"size": 10, "query": {"match_all": {}}, "sort": ["_doc"]}

    # control-before: the baseline the reopened index is compared against.
    status, baseline = _signed_request(ctx, "POST", f"{base}/{index}/_search", body=query)
    assert status == 200, f"the pre-close baseline search returned HTTP {status!r}: {baseline!r}"
    baseline_ids = _hit_ids(baseline)
    assert baseline_ids == doc_ids, (
        f"the pre-close baseline search returned {baseline_ids!r}, expected the four indexed ids "
        f"{doc_ids!r} -- without a real baseline the reopen would prove nothing"
    )

    # act: break exactly one thing -- close the index.
    status, close_body = _signed_request(ctx, "POST", f"{base}/{index}/_close")
    assert status == 200, f"_close returned HTTP {status!r}: {close_body!r}"
    assert close_body.get("acknowledged") is True, f"_close was not acknowledged: {close_body!r}"

    status, closed = _signed_request(ctx, "POST", f"{base}/{index}/_search", body=query)
    assert status == 400, (
        f"searching a closed index returned HTTP {status!r}, expected "
        f"400: {closed!r}"
    )
    assert _error_type(closed) == "index_closed_exception", (
        f"expected index_closed_exception, got {_error_type(closed)!r}: {closed!r}"
    )
    assert _error_names_index(closed, index), (
        f"index_closed_exception does not name the closed index {index!r}: {closed!r}"
    )
    # effect absent: a close must not delete anything, and it must not silently return an
    # empty result set instead of refusing.
    assert "hits" not in closed, (
        f"the refusal carried a hits section, so a lenient search silently replaced the "
        f"rejection with an empty result: {closed!r}"
    )
    status, cat = _signed_request(ctx, "GET", f"{base}/_cat/indices/{index}?format=json")
    assert status == 200, f"_cat/indices on the closed index returned HTTP {status!r}: {cat!r}"
    cat_rows = [r for r in cat if r.get("index") == index]
    assert len(cat_rows) == 1, (
        f"_cat/indices returned {len(cat_rows)!r} rows for {index!r}, expected exactly 1 -- "
        f"a closed index must still exist: {cat!r}"
    )
    assert cat_rows[0].get("status") == "close", (
        f"_cat/indices reports status {cat_rows[0].get('status')!r} for a closed index, expected "
        f"'close' -- a close must not delete the index: {cat_rows[0]!r}"
    )

    # control-after: undo the one broken thing and the identical search works again.
    status, open_body = _signed_request(ctx, "POST", f"{base}/{index}/_open")
    assert status == 200, f"_open returned HTTP {status!r}: {open_body!r}"
    assert open_body.get("acknowledged") is True, f"_open was not acknowledged: {open_body!r}"
    health = _wait_index_status(ctx, base, index, "yellow")
    assert health.get("status") in ("yellow", "green"), (
        f"reopened index health is {health.get('status')!r}: {health!r}"
    )
    status, _ = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"_refresh after the reopen returned HTTP {status!r}"
    status, reopened = _signed_request(ctx, "POST", f"{base}/{index}/_search", body=query)
    assert status == 200, f"the post-reopen search returned HTTP {status!r}: {reopened!r}"
    assert _hit_ids(reopened) == baseline_ids, (
        f"after reopening, the identical search returned {_hit_ids(reopened)!r}, expected the "
        f"pre-close set {baseline_ids!r} -- a close/open cycle must not lose documents"
    )

    # A closed index still bills storage, so delete it explicitly once reopened and confirm the
    # delete with an independent read, so a delete that silently no-ops cannot pass.
    status, delete_body = _signed_request(ctx, "DELETE", f"{base}/{index}")
    assert status == 200, f"deleting {index!r} returned HTTP {status!r}: {delete_body!r}"
    status, missing = _signed_request(ctx, "GET", f"{base}/{index}")
    assert status == 404, (
        f"an independent read after deleting {index!r} returned HTTP {status!r}, expected 404: "
        f"{missing!r}"
    )
    assert _error_type(missing) == "index_not_found_exception", (
        f"expected index_not_found_exception after deleting {index!r}, got "
        f"{_error_type(missing)!r}: {missing!r}"
    )
    assert _error_names_index(missing, index), (
        f"index_not_found_exception does not name the deleted index {index!r}: {missing!r}"
    )
    # Gone 2: the index listing no longer has a row for it.
    status, rows = _signed_request(ctx, "GET", f"{base}/_cat/indices?format=json")
    assert status == 200 and isinstance(rows, list), (
        f"_cat/indices expected 200 and a JSON list, got HTTP {status!r}: {rows!r}"
    )
    stale = [r for r in rows if r.get("index") == index]
    assert not stale, f"_cat/indices still lists the deleted index {index!r}: {stale!r}"
    # Gone 3: a mutation on the dead index is refused not-found, not acknowledged.
    status, reopen_dead = _signed_request(ctx, "POST", f"{base}/{index}/_open")
    assert status == 404, (
        f"_open on the deleted index {index!r} returned HTTP {status!r}, expected 404: {reopen_dead!r}"
    )
    assert _error_type(reopen_dead) == "index_not_found_exception", (
        f"_open on the deleted index: expected index_not_found_exception, got "
        f"{_error_type(reopen_dead)!r}: {reopen_dead!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
