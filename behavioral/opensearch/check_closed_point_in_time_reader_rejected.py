"""closed-point-in-time-reader-rejected."""
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

CHECK = "closed-point-in-time-reader-rejected"
GROUP = 'rejected'
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
        # Tagged at creation so tag-based cleanup can find leaked domains: it discovers what to
        # delete through the Resource Groups Tagging API and sees nothing else.
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: jitter every attempt (this spreads
    # concurrent runs' initial calls apart, not just retries), then back off harder on throttling.
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


def _hit_ids(result) -> list:
    return [h["_id"] for h in result.get("hits", {}).get("hits", [])]


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


# ===== end shared domain helpers =====

def _verified_domain_teardown(ctx, domain_name: str, timeout_s: float = 420.0) -> None:
    """Delete the domain INLINE and poll until the API confirms the deletion is committed.

    `on_cleanup` runs on a daemon thread joined with a 60 s cap and, by its own docstring, NEVER
    affects the verdict -- so a teardown that must be PROVEN cannot live only there. A domain that
    leaks bills per node-hour 24x7.

    The proof taken here is `DomainStatus.Deleted is True` (or an outright
    ResourceNotFoundException). Full disappearance from `describe_domain` takes a further ~10-15
    min of asynchronous teardown that no check can usefully sit through, but `Deleted: True` is the
    service stating the delete was accepted and is in progress, which is the strongest evidence
    available inside a check budget.
    """
    osc = ctx.client("opensearch")
    _delete_domain_quietly(osc, domain_name)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if last.get("Deleted") is True:
            return
        time.sleep(2)
    raise AssertionError(
        f"domain {domain_name!r} never reported Deleted=True within {timeout_s}s of DeleteDomain "
        f"(last status Deleted={last.get('Deleted')!r} Processing={last.get('Processing')!r}) -- "
        f"a domain that will not tear down bills per node-hour")


_SCENARIO = "closed-pit-reader-rejected"
_INDEX = "sim2real-behav-pitneg"
_DOCS = 50
_PAGE = 5
_GARBAGE_PIT_ID = "sim2real-not-a-pit-id"


def _walk_page(ctx, base: str, pit_id: str):
    return _signed_request(ctx, "POST", f"{base}/_search",
                           body={"size": _PAGE, "pit": {"id": pit_id, "keep_alive": "5m"},
                                 "sort": [{"sort_id": "asc"}]})


def _open_pit(ctx, base: str) -> str:
    status, body = _signed_request(
        ctx, "POST", f"{base}/{_INDEX}/_search/point_in_time?keep_alive=5m")
    assert status == 200, f"opening a point-in-time reader returned HTTP {status!r}: {body!r}"
    pit_id = body.get("pit_id")
    assert isinstance(pit_id, str) and pit_id, (
        f"the point-in-time response carried pit_id {pit_id!r}: {body!r}")
    return pit_id


def _live_total(ctx, base: str) -> int:
    status, result = _signed_request(ctx, "POST", f"{base}/{_INDEX}/_search",
                                     body={"size": 0, "track_total_hits": True,
                                           "query": {"match_all": {}}})
    assert status == 200, f"a live count returned HTTP {status!r}: {result!r}"
    return _total(result)


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A closed point-in-time reader is refused (HTTP 404 search_context_missing_exception) on
    `search_after`, a garbage id gets 400 illegal_argument_exception, and a fresh reader on the
    untouched index walks it fine.
    """
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    status, created = _signed_request(ctx, "PUT", f"{base}/{_INDEX}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"sort_id": {"type": "keyword"}}}})
    assert status == 200, f"creating index {_INDEX!r} returned HTTP {status!r}: {created!r}"
    _bulk_load(ctx, base, _INDEX,
               [(f"d-{i:03d}", {"sort_id": f"d-{i:03d}"}) for i in range(_DOCS)])
    status, _ = _signed_request(ctx, "POST", f"{base}/{_INDEX}/_refresh")
    assert status == 200, f"the seed _refresh returned HTTP {status!r}"

    pit_id = _open_pit(ctx, base)
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/_search/point_in_time",
                                           body={"pit_id": [pit_id]}))

    # --- setup proof: the reader works BEFORE the one thing is broken.
    status, first = _walk_page(ctx, base, pit_id)
    assert status == 200, f"a page through the live reader returned HTTP {status!r}: {first!r}"
    assert _hit_ids(first) == [f"d-{i:03d}" for i in range(_PAGE)], (
        f"the live reader returned {_hit_ids(first)!r}, expected the first {_PAGE} ids in sort "
        f"order -- the refusal below is only meaningful if the reader worked first")

    # --- break exactly one thing: close the reader.
    status, closed = _signed_request(ctx, "DELETE", f"{base}/_search/point_in_time",
                                     body={"pit_id": [pit_id]})
    assert status == 200, f"closing the reader returned HTTP {status!r}: {closed!r}"
    pits = closed.get("pits") or []
    assert len(pits) == 1 and pits[0].get("successful") is True, (
        f"closing the reader reported {closed!r}, expected exactly one entry with "
        f"successful=true")
    assert pits[0].get("pit_id") == pit_id, (
        f"the close response names pit_id {pits[0].get('pit_id')!r}, expected the id that was "
        f"closed")

    # --- the refusal, on a byte-identical request.
    status, refused = _walk_page(ctx, base, pit_id)
    assert status == 404, (
        f"reusing the CLOSED reader answered HTTP {status!r}, expected 404. Body: {refused!r} -- "
        f"an emulator that serves live results through a closed reader is exactly the "
        f"over-permissiveness this check exists to catch")
    assert _root_cause_type(refused) == "search_context_missing_exception", (
        f"reusing the closed reader reported root cause "
        f"{_root_cause_type(refused)!r}, expected 'search_context_missing_exception': {refused!r}")
    assert refused.get("status") == 404, (
        f"the refusal body carries status {refused.get('status')!r}, expected 404: {refused!r}")

    # --- effect absent: closing a reader must not touch the data it was reading.
    assert _live_total(ctx, base) == _DOCS, (
        f"a live search reports {_live_total(ctx, base)!r} documents after the reader was closed, "
        f"expected all {_DOCS} -- closing a reader is not a delete")
    status, direct = _signed_request(ctx, "GET", f"{base}/{_INDEX}/_doc/d-000")
    assert status == 200, (
        f"a document the closed reader had returned is no longer readable (HTTP {status!r}): "
        f"{direct!r}")

    # --- a garbage handle is a DIFFERENT refusal: the engine must not collapse the two.
    status, garbage = _signed_request(
        ctx, "POST", f"{base}/_search",
        body={"size": _PAGE, "pit": {"id": _GARBAGE_PIT_ID}, "sort": [{"sort_id": "asc"}]})
    assert status == 400, (
        f"a syntactically invalid pit id answered HTTP {status!r}, expected 400: {garbage!r}")
    assert _root_cause_type(garbage) == "illegal_argument_exception", (
        f"an invalid pit id reported root cause {_root_cause_type(garbage)!r}, expected "
        f"'illegal_argument_exception' -- distinct from the 404 a valid-but-closed id gets, and an "
        f"engine that answers both the same way has not implemented reader lifecycle: {garbage!r}")
    assert _GARBAGE_PIT_ID in json.dumps(garbage), (
        f"the invalid-id refusal does not quote the id it rejected: {garbage!r}")

    # --- control: a NEW reader on the same index, with the same request shape, succeeds.
    fresh_id = _open_pit(ctx, base)
    assert fresh_id != pit_id, (
        f"opening a new reader returned the same id {fresh_id!r} that was just closed")
    status, fresh = _walk_page(ctx, base, fresh_id)
    assert status == 200, f"a page through the FRESH reader returned HTTP {status!r}: {fresh!r}"
    assert _hit_ids(fresh) == [f"d-{i:03d}" for i in range(_PAGE)], (
        f"the fresh reader returned {_hit_ids(fresh)!r}, expected the same first {_PAGE} ids -- so "
        f"the 404 above was about the closed reader, not a broken index")
    status, closed_fresh = _signed_request(ctx, "DELETE", f"{base}/_search/point_in_time",
                                           body={"pit_id": [fresh_id]})
    assert status == 200, f"closing the fresh reader returned HTTP {status!r}: {closed_fresh!r}"

    _signed_request(ctx, "DELETE", f"{base}/{_INDEX}")
    _verified_domain_teardown(ctx, domain)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
