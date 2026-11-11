"""scroll-pagination-returns-each-document-exactly-once."""
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

CHECK = "scroll-pagination-returns-each-document-exactly-once"
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
# The CONTROL-PLANE convergence counterpart, for a domain that was accepted and never converged.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state: a failure on every target.

    The message carries the sentinel so the failure is attributed to the target.
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
    # CreateDomain is aggressively rate limited per account: jitter, then back off on throttling.
    # The jitter lives inside the bounded retry loop (not a bare pre-loop sleep) so the whole
    # dance is one bounded wait with a deadline, not an unconditional sleep.
    for attempt in range(12):
        time.sleep(random.uniform(0, 20.0) if attempt == 0 else 6.0 * attempt + random.uniform(0, 6.0))
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1200.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep.

    The budget keeps the whole check under 30 minutes.
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
    raise _never_ready(
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


def _hit_ids(result) -> list:
    return [h["_id"] for h in result.get("hits", {}).get("hits", [])]


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


# ===== end self-contained helpers =====

_SCENARIO = "scroll-pagination-exactly-once"


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A scroll over 25 documents at size 10 returns each document exactly once across pages 10/10/5
    and an empty page, and five documents indexed after the scroll opened never appear in it."""
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = "sim2real-behav-scroll"
    # One primary, no replicas is load-bearing: _doc-sorted page sizes over a single shard are
    # the engine's own paging, not a coordinator trimming several shards' contributions.
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"n": {"type": "integer"}}}})
    assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"

    expected_ids = [f"doc-{i:02d}" for i in range(25)]
    _bulk_load(ctx, base, index, [(i, {"n": n}) for n, i in enumerate(expected_ids)])
    status, _ = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"_refresh before opening the scroll returned HTTP {status!r}"

    status, page = _signed_request(ctx, "POST", f"{base}/{index}/_search?scroll=2m",
                                   body={"size": 10, "query": {"match_all": {}},
                                         "sort": ["_doc"]})
    assert status == 200, f"opening the scroll returned HTTP {status!r}: {page!r}"
    scroll_id = page.get("_scroll_id")
    assert isinstance(scroll_id, str) and scroll_id, (
        f"the first scroll page carried no _scroll_id, so there is nothing to page with: {page!r}"
    )
    page_sizes = [len(page.get("hits", {}).get("hits", []))]
    all_ids = _hit_ids(page)

    # Written AFTER the scroll opened: a non-point-in-time implementation leaks these into it.
    late_ids = [f"late-{i:02d}" for i in range(5)]
    _bulk_load(ctx, base, index, [(i, {"n": 100 + n}) for n, i in enumerate(late_ids)])
    status, _ = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"_refresh of the late writes returned HTTP {status!r}"

    # Bounded by page count, deliberately: 25 documents at size 10 cannot need more than a
    # handful of pages, so a target that never empties the scroll fails here.
    for _ in range(8):
        status, page = _signed_request(ctx, "POST", f"{base}/_search/scroll",
                                       body={"scroll": "2m", "scroll_id": scroll_id})
        assert status == 200, f"paging the scroll returned HTTP {status!r}: {page!r}"
        hits = page.get("hits", {}).get("hits", [])
        page_sizes.append(len(hits))
        all_ids += [h["_id"] for h in hits]
        scroll_id = page.get("_scroll_id", scroll_id)
        if not hits:
            break

    assert page_sizes == [10, 10, 5, 0], (
        f"the scroll produced page sizes {page_sizes!r}, expected [10, 10, 5, 0] for 25 documents "
        f"at size 10 followed by one empty page"
    )
    assert sorted(all_ids) == sorted(expected_ids), (
        f"the scroll returned {len(all_ids)!r} ids, expected exactly the 25 originals; missing "
        f"{sorted(set(expected_ids) - set(all_ids))!r}, unexpected "
        f"{sorted(set(all_ids) - set(expected_ids))!r}"
    )
    assert len(all_ids) == len(set(all_ids)), (
        f"the scroll returned duplicate ids: "
        f"{sorted(i for i in set(all_ids) if all_ids.count(i) > 1)!r}"
    )
    leaked = [i for i in all_ids if i.startswith("late-")]
    assert leaked == [], (
        f"documents indexed after the scroll opened leaked into it: {leaked!r} -- a scroll is a "
        f"point-in-time view of the segments it opened over"
    )

    # The late writes really are live -- so the absence above is the scroll's isolation and not
    # a failed write.
    status, fresh = _signed_request(ctx, "POST", f"{base}/{index}/_search",
                                    body={"size": 0, "query": {"match_all": {}},
                                          "track_total_hits": True})
    assert status == 200, f"the fresh search returned HTTP {status!r}: {fresh!r}"
    assert _total(fresh) == 30, (
        f"a fresh search sees {_total(fresh)!r} documents, expected 30 -- the five late writes "
        f"must be visible outside the scroll"
    )

    # A leaked scroll context holds segments open: clear it in-band and assert the engine agreed.
    status, cleared = _signed_request(ctx, "DELETE", f"{base}/_search/scroll",
                                      body={"scroll_id": [scroll_id]})
    assert status == 200, f"clearing the scroll returned HTTP {status!r}: {cleared!r}"
    assert cleared.get("succeeded") is True, (
        f"DELETE _search/scroll was not acknowledged: {cleared!r}"
    )

    _signed_request(ctx, "DELETE", f"{base}/{index}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
